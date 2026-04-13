import asyncio
import json
import re
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import aiohttp
from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.message_components import Plain
from astrbot.api.star import Context, Star, register
from astrbot.core import AstrBotConfig
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import (
    AiocqhttpMessageEvent,
)
from astrbot.core.star.filter.event_message_type import EventMessageType


@register("sensitive_word_monitor", "JuanYi", "敏感词撤回插件", "1.0.0")
class SensitiveWordMonitor(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        self.context = context

        # 初始化配置
        self.group_whitelist = config.get(
            "group_whitelist", ["QQ:GroupMessage:1030157691"]
        )
        self.admin_qq_list = config.get("admin_qq_list", ["QQ:FriendMessage:962063168"])
        self.api_endpoint_enabled = config.get("api_endpoint_enabled", True)
        self.api_endpoint = config.get("api_endpoint", "")
        self.group_notice_enabled = config.get("group_notice_enabled", True)
        self.notice_template = config.get("notice_template", "")
        self.admin_notice_template = config.get("admin_notice_template", "")
        self.statistics_enabled = config.get("statistics_enabled", True)
        self.cooldown_seconds = config.get("cooldown_seconds", 60)
        self.enable_auto_ban = config.get("enable_auto_ban", True)
        self.exempt_roles = config.get("exempt_roles", ["owner", "admin"])
        self.violation_log_enabled = config.get("violation_log_enabled", True)
        self.max_log_days = config.get("max_log_days", 30)
        self.enable_message_delete = config.get("enable_message_delete", True)
        self.bypass_rate_limit = config.get("bypass_rate_limit", True)
        self.enable_local_check = config.get("enable_local_check", True)
        self.debug_mode = config.get("debug_mode", False)

        # 自定义敏感词
        self.custom_forbidden_words = set(config.get("custom_forbidden_words", []))
        self.local_check_patterns = self._compile_local_patterns()

        # 自定义白名单词
        self.custom_white_words = set(config.get("custom_white_words", []))
        self.white_word_check_patterns = self._compile_white_word_patterns()

        # 禁言规则
        ban_rules = config.get("ban_rules", {})
        self.first_ban_duration = ban_rules.get("first_ban_duration", 60)
        self.second_ban_duration = ban_rules.get("second_ban_duration", 600)
        self.third_ban_duration = ban_rules.get("third_ban_duration", 86400)
        self.reset_time = ban_rules.get("reset_time", 4)

        # 统计数据结构
        self.statistics: Dict[str, Dict] = {
            "total_checks": 0,
            "sensitive_detected": 0,
            "auto_bans": 0,
            "by_group": {},
            "by_user": {},
            "by_word": {},
        }

        # 冷却时间记录
        self.cooldown_users: Dict[str, float] = {}

        # 消息ID缓存，用于绕过限流
        self.message_cache: Dict[str, Dict] = {}

        # 违规记录数据库
        self.db_path = Path("data/plugin_data/sensitive_word_monitor/violations.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()

        logger.info("=" * 60)
        logger.info(f"敏感词撤回插件 v0.0.1 已加载")
        logger.info(f"监控群聊：{len(self.group_whitelist)}个")
        logger.info(f"管理员：{len(self.admin_qq_list)}个")
        logger.info(f"自定义敏感词：{len(self.custom_forbidden_words)}个")
        logger.info(f"自定义白名单词：{len(self.custom_white_words)}个")
        logger.info(
            f"禁言规则：{self.first_ban_duration}s/{self.second_ban_duration}s/{self.third_ban_duration}s"
        )
        logger.info(f"绕过限流：{'是' if self.bypass_rate_limit else '否'}")
        logger.info("=" * 60)

    def _compile_local_patterns(self) -> List[re.Pattern]:
        """编译本地敏感词正则表达式"""
        patterns = []
        for word in self.custom_forbidden_words:
            if word:
                try:
                    pattern = re.compile(re.escape(word), re.IGNORECASE)
                    patterns.append(pattern)
                except Exception as e:
                    logger.error(f"编译敏感词正则失败 {word}: {e}")
        return patterns

    def _compile_white_word_patterns(self) -> List[re.Pattern]:
        """编译本地白名单词正则表达式"""
        patterns = []
        for word in self.custom_white_words:
            if word:
                try:
                    pattern = re.compile(re.escape(word), re.IGNORECASE)
                    patterns.append(pattern)
                except Exception as e:
                    logger.error(f"编译白名单词正则失败 {word}: {e}")
        return patterns

    def local_check(self, text: str) -> Tuple[bool, List[str]]:
        """本地敏感词检测"""
        if not self.enable_local_check or not self.local_check_patterns:
            return False, []

        found_words = []
        for pattern in self.local_check_patterns:
            matches = pattern.findall(text)
            if matches:
                found_words.extend(matches)

        return bool(found_words), list(set(found_words))

    def white_word_check(self, text: str) -> Tuple[bool, List[str]]:
        if not self.white_word_check_patterns:
            return False, []

        found_words = []
        for pattern in self.white_word_check_patterns:
            matches = pattern.findall(text)
            if matches:
                found_words.extend(matches)

        return bool(found_words), list(set(found_words))

    def init_database(self):
        """初始化违规记录数据库"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS violations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    user_name TEXT,
                    violation_count INTEGER DEFAULT 1,
                    forbidden_words TEXT,
                    original_text TEXT,
                    ban_duration INTEGER,
                    last_violation_date DATE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_group_user ON violations(group_id, user_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_last_date ON violations(last_violation_date)"
            )

            conn.commit()
            conn.close()
            if self.debug_mode:
                logger.debug("违规记录数据库初始化完成")
        except Exception as e:
            logger.error(f"初始化数据库失败：{e}")

    def is_whitelist_group(self, group_id: str) -> bool:
        """检查群聊是否在白名单中"""
        group_umo = f"QQ:GroupMessage:{group_id}"
        return group_umo in self.group_whitelist

    def should_check_user(self, user_id: str) -> bool:
        """检查用户是否在冷却时间内"""
        if self.bypass_rate_limit:
            return True

        now = time.time()
        last_check = self.cooldown_users.get(user_id, 0)

        if now - last_check >= self.cooldown_seconds:
            self.cooldown_users[user_id] = now
            return True
        return False

    async def get_user_role(self, event: AiocqhttpMessageEvent) -> Optional[str]:
        """获取用户在群内的角色"""
        try:
            if hasattr(event, "is_admin") and callable(event.is_admin):
                if event.is_admin():
                    return "admin"

            if hasattr(event.message_obj, "sender"):
                sender = event.message_obj.sender
                if hasattr(sender, "role"):
                    role = getattr(sender, "role", "")
                    if role == "owner":
                        return "owner"
                    elif role == "admin":
                        return "admin"

            return None
        except Exception as e:
            if self.debug_mode:
                logger.error(f"获取用户角色失败：{e}")
            return None

    def is_exempt_from_ban(self, role: Optional[str]) -> bool:
        """检查用户是否免禁言"""
        if not role:
            return False
        return role.lower() in [r.lower() for r in self.exempt_roles]

    async def get_violation_info(self, group_id: str, user_id: str) -> Tuple[int, str]:
        """获取用户违规信息（次数，最后违规日期）"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.now()
            reset_datetime = datetime(
                now.year, now.month, now.day, self.reset_time, 0, 0
            )

            if now.hour < self.reset_time:
                reset_datetime -= timedelta(days=1)

            cursor.execute(
                """
                SELECT violation_count, last_violation_date
                FROM violations
                WHERE group_id = ? AND user_id = ?
                ORDER BY last_violation_date DESC
                LIMIT 1
            """,
                (group_id, user_id),
            )

            result = cursor.fetchone()
            conn.close()

            if result:
                violation_count, last_date_str = result
                last_date = datetime.strptime(last_date_str, "%Y-%m-%d").date()
                today = now.date()

                if last_date < today:
                    return 1, str(today)
                else:
                    return violation_count + 1, last_date_str
            else:
                return 1, str(now.date())

        except Exception as e:
            if self.debug_mode:
                logger.error(f"获取违规信息失败：{e}")
            return 1, str(datetime.now().date())

    async def update_violation_record(
        self,
        group_id: str,
        user_id: str,
        user_name: str,
        violation_count: int,
        forbidden_words: List[str],
        original_text: str,
        ban_duration: int,
    ):
        """更新违规记录"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            today = datetime.now().date()

            cursor.execute(
                """
                INSERT OR REPLACE INTO violations
                (group_id, user_id, user_name, violation_count, forbidden_words,
                 original_text, ban_duration, last_violation_date, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
                (
                    group_id,
                    user_id,
                    user_name,
                    violation_count,
                    json.dumps(forbidden_words, ensure_ascii=False),
                    original_text[:500],
                    ban_duration,
                    str(today),
                ),
            )

            cutoff_date = (datetime.now() - timedelta(days=self.max_log_days)).date()
            cursor.execute(
                "DELETE FROM violations WHERE last_violation_date < ?",
                (str(cutoff_date),),
            )

            conn.commit()
            conn.close()

            if self.debug_mode:
                logger.debug(
                    f"更新违规记录：群{group_id} 用户{user_id} 第{violation_count}次违规"
                )

        except Exception as e:
            logger.error(f"更新违规记录失败：{e}")

    async def delete_message(self, event: AiocqhttpMessageEvent) -> bool:
        """撤回消息"""
        try:
            if not self.enable_message_delete:
                return False

            message_id = event.message_obj.message_id
            if hasattr(event.bot, "delete_msg"):
                await event.bot.delete_msg(message_id=message_id)
                if self.debug_mode:
                    logger.debug(f"已撤回消息 {message_id}")
                return True
            else:
                logger.warning("当前平台不支持消息撤回")
                return False
        except Exception as e:
            if self.debug_mode:
                logger.error(f"撤回消息失败：{e}")
            return False

    async def check_sensitive_words(self, text: str) -> Optional[Dict]:
        """调用敏感词检测API"""
        if not text or not text.strip():
            return None

        try:
            async with aiohttp.ClientSession() as session:
                payload = {"text": text}
                headers = {"Content-Type": "application/json"}

                async with session.post(
                    self.api_endpoint, json=payload, headers=headers, timeout=10
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result
                    else:
                        if self.debug_mode:
                            logger.error(
                                f"敏感词API请求失败，状态码：{response.status}"
                            )
                        return None
        except Exception as e:
            if self.debug_mode:
                logger.error(f"敏感词检测API调用异常：{e}")
            return None

    async def ban_user(
        self, event: AiocqhttpMessageEvent, user_id: str, duration: int
    ) -> bool:
        """禁言用户"""
        try:
            group_id = event.get_group_id()

            if hasattr(event, "bot") and hasattr(event.bot, "set_group_ban"):
                await event.bot.set_group_ban(
                    group_id=int(group_id), user_id=int(user_id), duration=duration
                )
                if self.debug_mode:
                    logger.debug(f"已禁言用户 {user_id}，时长 {duration} 秒")
                return True
            else:
                logger.warning("当前平台不支持禁言操作")
                return False

        except Exception as e:
            logger.error(f"禁言用户失败：{e}")
            return False

    def update_statistics(
        self,
        group_id: str,
        user_id: str,
        forbidden_words: List[str],
        has_sensitive: bool,
        was_banned: bool = False,
    ):
        """更新统计信息"""
        if not self.statistics_enabled:
            return

        self.statistics["total_checks"] += 1

        if has_sensitive:
            self.statistics["sensitive_detected"] += 1

            if was_banned:
                self.statistics["auto_bans"] += 1

            if group_id not in self.statistics["by_group"]:
                self.statistics["by_group"][group_id] = {
                    "total": 0,
                    "bans": 0,
                    "users": set(),
                    "words": {},
                }
            self.statistics["by_group"][group_id]["total"] += 1
            if was_banned:
                self.statistics["by_group"][group_id]["bans"] += 1
            self.statistics["by_group"][group_id]["users"].add(user_id)

            user_key = f"{group_id}:{user_id}"
            if user_key not in self.statistics["by_user"]:
                self.statistics["by_user"][user_key] = {"total": 0, "bans": 0}
            self.statistics["by_user"][user_key]["total"] += 1
            if was_banned:
                self.statistics["by_user"][user_key]["bans"] += 1

            for word in forbidden_words:
                if word not in self.statistics["by_word"]:
                    self.statistics["by_word"][word] = {"total": 0, "bans": 0}
                self.statistics["by_word"][word]["total"] += 1
                if was_banned:
                    self.statistics["by_word"][word]["bans"] += 1

    def format_notice(self, template: str, **kwargs) -> str:
        """格式化提醒消息"""
        try:
            return template.format(**kwargs)
        except Exception as e:
            if self.debug_mode:
                logger.error(f"格式化消息失败：{e}")
            return template

    async def send_admin_notice(
        self,
        group_id: str,
        user_id: str,
        user_name: str,
        forbidden_words: List[str],
        original_text: str,
        violation_count: int,
        ban_duration: int,
    ):
        """给所有管理员发送私聊提醒"""
        if not self.admin_qq_list:
            return

        for admin_umo in self.admin_qq_list:
            try:
                notice_content = self.format_notice(
                    self.admin_notice_template,
                    group_id=group_id,
                    user_name=user_name,
                    user_id=user_id,
                    forbidden_words=", ".join(forbidden_words),
                    original_text=original_text[:100]
                    + ("..." if len(original_text) > 100 else ""),
                    violation_count=violation_count,
                    ban_duration=ban_duration,
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )

                # 添加严重性提示
                if violation_count >= 3:
                    notice_content = f"⚠️⚠️⚠️ 严重违规！第三次违规！\n" + notice_content

                # 发送私聊消息
                message_chain = MessageChain()
                message_chain.chain = [Plain(notice_content)]

                await self.context.send_message(admin_umo, message_chain)

                if self.debug_mode:
                    logger.debug(
                        f"已向管理员 {admin_umo} 发送敏感词提醒（第{violation_count}次违规）"
                    )
            except Exception as e:
                logger.error(f"向管理员 {admin_umo} 发送提醒失败：{e}")

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def monitor_group_message(self, event: AiocqhttpMessageEvent):
        """监控群消息，检测敏感词并执行阶梯式禁言"""
        try:
            # 获取基本信息
            group_id = event.get_group_id()
            user_id = str(event.message_obj.sender.user_id)
            user_name = event.get_sender_name()
            message_text = event.message_str

            if self.debug_mode:
                logger.debug(
                    f"收到消息：群{group_id} 用户{user_id} 内容：{message_text[:50]}"
                )

            # 检查是否在白名单群聊中
            if not self.is_whitelist_group(group_id):
                if self.debug_mode:
                    logger.debug(f"群{group_id}不在白名单中，忽略")
                return

            # 检查冷却时间
            if not self.should_check_user(user_id):
                if self.debug_mode:
                    logger.debug(f"用户{user_id}在冷却时间内，忽略")
                return


            # 本地敏感词检测
            local_hit, local_words = self.local_check(message_text)
            if local_hit and local_words:
                logger.info(f"本地检测到敏感词：{local_words}")

                # 检测是否在白名单词语内
                white_hit, white_words = self.white_word_check(message_text)
                if white_hit and local_words:
                    logger.info(f"本地检测到白名单词：{white_words}，跳过后续操作")
                    return
                # 获取用户违规信息
                violation_count, violation_date = await self.get_violation_info(
                    group_id, user_id
                )

                # 确定禁言时长
                ban_duration = 0
                if self.enable_auto_ban:
                    if violation_count == 1:
                        ban_duration = self.first_ban_duration
                    elif violation_count == 2:
                        ban_duration = self.second_ban_duration
                    else:
                        ban_duration = self.third_ban_duration

                # 检测用户身份
                user_role = await self.get_user_role(event)
                # 检查用户是否可以撤回消息
                if not self.is_exempt_from_ban(user_role):
                    await self.delete_message(event)

                # 检查用户是否免禁言
                was_banned = False

                if ban_duration > 0 and not self.is_exempt_from_ban(user_role):
                    ban_success = await self.ban_user(event, user_id, ban_duration)
                    was_banned = ban_success

                # 更新违规记录
                await self.update_violation_record(
                    group_id,
                    user_id,
                    user_name,
                    violation_count,
                    local_words,
                    message_text,
                    ban_duration,
                )

                # 更新统计
                self.update_statistics(group_id, user_id, local_words, True, was_banned)

                # 发送群内提醒
                if self.group_notice_enabled and self.notice_template:
                    notice_content = self.format_notice(
                        self.notice_template,
                        forbidden_words=", ".join(local_words),
                        original_text=message_text[:50]
                        + ("..." if len(message_text) > 50 else ""),
                        violation_count=violation_count,
                        ban_duration=ban_duration,
                    )

                    if was_banned:
                        if ban_duration >= 3600:
                            hours = ban_duration // 3600
                            notice_content += f"\n已执行禁言 {hours} 小时"
                        elif ban_duration >= 60:
                            minutes = ban_duration // 60
                            notice_content += f"\n已执行禁言 {minutes} 分钟"
                        else:
                            notice_content += f"\n已执行禁言 {ban_duration} 秒"

                    yield event.plain_result(notice_content)

                # 发送管理员通知（每次违规都发送）
                await self.send_admin_notice(
                    group_id,
                    user_id,
                    user_name,
                    local_words,
                    message_text,
                    violation_count,
                    ban_duration,
                )

                logger.info(
                    f"本地检测敏感词 - 群{group_id} 用户{user_id}: {local_words}（第{violation_count}次违规）"
                )
                return

            # API敏感词检测
            if self.api_endpoint_enabled == False:
                return
            result = await self.check_sensitive_words(message_text)

            if result and result.get("status") == "forbidden":
                forbidden_words = result.get("forbidden_words", [])
                original_text = result.get("original_text", "")

                logger.info(f"API检测到敏感词：{forbidden_words}")

                # 获取用户违规信息
                violation_count, violation_date = await self.get_violation_info(
                    group_id, user_id
                )

                # 确定禁言时长
                ban_duration = 0
                if self.enable_auto_ban:
                    if violation_count == 1:
                        ban_duration = self.first_ban_duration
                    elif violation_count == 2:
                        ban_duration = self.second_ban_duration
                    else:
                        ban_duration = self.third_ban_duration

                # 撤回消息
                await self.delete_message(event)

                # 检查用户是否免禁言
                user_role = await self.get_user_role(event)
                was_banned = False

                if ban_duration > 0 and not self.is_exempt_from_ban(user_role):
                    ban_success = await self.ban_user(event, user_id, ban_duration)
                    was_banned = ban_success

                # 更新违规记录
                await self.update_violation_record(
                    group_id,
                    user_id,
                    user_name,
                    violation_count,
                    forbidden_words,
                    original_text,
                    ban_duration,
                )

                # 更新统计
                self.update_statistics(
                    group_id, user_id, forbidden_words, True, was_banned
                )

                # 发送群内提醒
                if self.group_notice_enabled and self.notice_template:
                    notice_content = self.format_notice(
                        self.notice_template,
                        forbidden_words=", ".join(forbidden_words),
                        original_text=original_text[:50]
                        + ("..." if len(original_text) > 50 else ""),
                        violation_count=violation_count,
                        ban_duration=ban_duration,
                    )

                    if was_banned:
                        if ban_duration >= 3600:
                            hours = ban_duration // 3600
                            notice_content += f"\n已执行禁言 {hours} 小时"
                        elif ban_duration >= 60:
                            minutes = ban_duration // 60
                            notice_content += f"\n已执行禁言 {minutes} 分钟"
                        else:
                            notice_content += f"\n已执行禁言 {ban_duration} 秒"

                    yield event.plain_result(notice_content)

                # 发送管理员通知（每次违规都发送）
                await self.send_admin_notice(
                    group_id,
                    user_id,
                    user_name,
                    forbidden_words,
                    original_text,
                    violation_count,
                    ban_duration,
                )

                logger.info(
                    f"API检测敏感词 - 群{group_id} 用户{user_id}: {forbidden_words}（第{violation_count}次违规）"
                )
            else:
                # 更新统计（无敏感词）
                self.update_statistics(group_id, user_id, [], False)

        except Exception as e:
            logger.error(f"敏感词撤回处理异常：{e}")
            if self.debug_mode:
                import traceback

                logger.error(f"详细堆栈：{traceback.format_exc()}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("敏感词统计")
    async def show_statistics(self, event: AiocqhttpMessageEvent):
        """显示统计信息"""
        if not self.statistics_enabled:
            yield event.plain_result("统计功能未启用")
            return

        try:
            group_id = event.get_group_id()
            user_id = str(event.message_obj.sender.user_id)

            if not self.is_whitelist_group(group_id) and not any(
                admin_umo.endswith(user_id) for admin_umo in self.admin_qq_list
            ):
                yield event.plain_result("权限不足")
                return

            stats = self.statistics

            message = "📊 敏感词检测统计\n"
            message += f"总检测次数：{stats['total_checks']}\n"
            message += f"检测到敏感词：{stats['sensitive_detected']}次\n"
            message += f"自动禁言：{stats.get('auto_bans', 0)}次\n"
            message += f"检测率：{stats['sensitive_detected'] / max(stats['total_checks'], 1) * 100:.1f}%\n\n"

            if group_id in stats["by_group"]:
                group_stats = stats["by_group"][group_id]
                message += f"本群统计：\n"
                message += f"- 敏感词次数：{group_stats['total']}\n"
                message += f"- 自动禁言：{group_stats.get('bans', 0)}次\n"
                message += f"- 涉及用户数：{len(group_stats['users'])}\n\n"

            if stats["by_word"]:
                sorted_words = sorted(
                    stats["by_word"].items(), key=lambda x: x[1]["total"], reverse=True
                )[:5]
                message += "高频敏感词：\n"
                for word, data in sorted_words:
                    message += (
                        f"- {word}: {data['total']}次（禁言{data.get('bans', 0)}次）\n"
                    )

            yield event.plain_result(message)

        except Exception as e:
            logger.error(f"生成统计信息失败：{e}")
            yield event.plain_result("统计信息生成失败")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("违规记录")
    async def show_violation_records(
        self, event: AiocqhttpMessageEvent, target_user: str = None
    ):
        """查看违规记录"""
        try:
            group_id = event.get_group_id()
            user_id = str(event.message_obj.sender.user_id)

            if not self.is_whitelist_group(group_id) and not any(
                admin_umo.endswith(user_id) for admin_umo in self.admin_qq_list
            ):
                yield event.plain_result("权限不足")
                return

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            if target_user:
                cursor.execute(
                    """
                    SELECT user_name, violation_count, last_violation_date, ban_duration,
                           forbidden_words, created_at
                    FROM violations
                    WHERE group_id = ? AND user_id = ?
                    ORDER BY last_violation_date DESC
                """,
                    (group_id, target_user),
                )
            else:
                cursor.execute(
                    """
                    SELECT user_id, user_name, violation_count, last_violation_date,
                           ban_duration, forbidden_words, created_at
                    FROM violations
                    WHERE group_id = ?
                    ORDER BY last_violation_date DESC, violation_count DESC
                    LIMIT 20
                """,
                    (group_id,),
                )

            records = cursor.fetchall()
            conn.close()

            if not records:
                yield event.plain_result("暂无违规记录")
                return

            message = "📋 违规记录\n"

            for record in records:
                if target_user:
                    (
                        user_name,
                        violation_count,
                        last_date,
                        ban_duration,
                        forbidden_words,
                        created_at,
                    ) = record
                    user_id = target_user
                else:
                    (
                        user_id,
                        user_name,
                        violation_count,
                        last_date,
                        ban_duration,
                        forbidden_words,
                        created_at,
                    ) = record

                words = json.loads(forbidden_words) if forbidden_words else []
                words_str = ", ".join(words[:3])
                if len(words) > 3:
                    words_str += f" 等{len(words)}个"

                message += f"\n用户：{user_name}({user_id})\n"
                message += f"违规次数：{violation_count}次\n"
                message += f"最近违规：{last_date}\n"
                if ban_duration > 0:
                    if ban_duration >= 3600:
                        hours = ban_duration // 3600
                        message += f"禁言时长：{hours}小时\n"
                    elif ban_duration >= 60:
                        minutes = ban_duration // 60
                        message += f"禁言时长：{minutes}分钟\n"
                    else:
                        message += f"禁言时长：{ban_duration}秒\n"
                message += f"敏感词：{words_str}\n"
                message += "-" * 20

            yield event.plain_result(message)

        except Exception as e:
            logger.error(f"查看违规记录失败：{e}")
            yield event.plain_result("查看违规记录失败")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("重置违规记录")
    async def reset_violation_record(
        self, event: AiocqhttpMessageEvent, target_user: str = None
    ):
        """重置违规记录"""
        try:
            user_id = str(event.message_obj.sender.user_id)

            if not any(admin_umo.endswith(user_id) for admin_umo in self.admin_qq_list):
                yield event.plain_result("仅管理员可重置违规记录")
                return

            group_id = event.get_group_id()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            if target_user:
                cursor.execute(
                    "DELETE FROM violations WHERE group_id = ? AND user_id = ?",
                    (group_id, target_user),
                )
                affected = cursor.rowcount
                message = (
                    f"✅ 已重置用户 {target_user} 的违规记录（清除 {affected} 条记录）"
                )
            else:
                cursor.execute("DELETE FROM violations WHERE group_id = ?", (group_id,))
                affected = cursor.rowcount
                message = f"✅ 已重置本群所有违规记录（清除 {affected} 条记录）"

            conn.commit()
            conn.close()

            yield event.plain_result(message)
            logger.info(f"违规记录已重置：群{group_id} 用户{target_user or 'ALL'}")

        except Exception as e:
            logger.error(f"重置违规记录失败：{e}")
            yield event.plain_result("重置失败")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("测试违规")
    async def test_violation(self, event: AiocqhttpMessageEvent, count: int = 1):
        """测试违规功能"""
        try:
            user_id = str(event.message_obj.sender.user_id)

            if not any(admin_umo.endswith(user_id) for admin_umo in self.admin_qq_list):
                yield event.plain_result("仅管理员可测试违规")
                return

            if count < 1 or count > 3:
                yield event.plain_result("违规次数范围：1-3")
                return

            group_id = event.get_group_id()
            user_name = event.get_sender_name()

            # 模拟违规
            forbidden_words = ["测试敏感词"]
            original_text = f"这是第{count}次违规测试"

            # 确定禁言时长
            if count == 1:
                ban_duration = self.first_ban_duration
            elif count == 2:
                ban_duration = self.second_ban_duration
            else:
                ban_duration = self.third_ban_duration

            # 发送测试通知给所有管理员
            for admin_umo in self.admin_qq_list:
                try:
                    notice_content = f"🧪 测试通知\n群聊：{group_id}\n用户：{user_name} ({user_id})\n模拟违规：第{count}次\n敏感词：{', '.join(forbidden_words)}\n禁言时长：{ban_duration}秒\n时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

                    message_chain = MessageChain()
                    message_chain.chain = [Plain(notice_content)]

                    await self.context.send_message(admin_umo, message_chain)

                    if self.debug_mode:
                        logger.debug(f"已向管理员 {admin_umo} 发送测试通知")
                except Exception as e:
                    logger.error(f"发送测试通知失败：{e}")

            yield event.plain_result(f"✅ 已发送第{count}次违规测试通知")

        except Exception as e:
            logger.error(f"测试违规失败：{e}")
            yield event.plain_result("测试失败")


    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("敏感词测试")
    async def test_sensitive(self, event: AiocqhttpMessageEvent, text: str = None):
        """测试敏感词检测"""
        try:
            if not text:
                # 尝试获取引用的消息
                if hasattr(event, "message_obj") and event.message_obj.message:
                    text_parts = []
                    for component in event.message_obj.message:
                        if component.type == "Plain":
                            text_parts.append(component.text)
                    text = " ".join(text_parts)

                if not text:
                    yield event.plain_result("请提供要检测的文本")
                    return

            # 本地检测
            local_hit, local_words = self.local_check(text)
            if local_hit:
                response = f"🔍 本地检测结果：\n检测到敏感词：{', '.join(local_words)}"
                yield event.plain_result(response)
                return

            # API检测
            result = await self.check_sensitive_words(text)

            if result:
                if result.get("status") == "forbidden":
                    forbidden_words = result.get("forbidden_words", [])
                    original_text = result.get("original_text", "")
                    masked_text = result.get("masked_text", "")

                    response = "🔍 API检测结果：\n"
                    response += f"状态：发现敏感词\n"
                    response += f"敏感词：{', '.join(forbidden_words)}\n"
                    response += f"原文：{original_text[:100]}{'...' if len(original_text) > 100 else ''}\n"
                    response += f"处理后：{masked_text[:100]}{'...' if len(masked_text) > 100 else ''}"
                else:
                    response = "✅ 未检测到敏感词"
            else:
                response = "❌ 检测失败，请稍后重试"

            yield event.plain_result(response)

        except Exception as e:
            logger.error(f"敏感词测试失败：{e}")
            yield event.plain_result("测试失败")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("添加敏感词")
    async def add_forbidden_word(self, event: AiocqhttpMessageEvent, word: str):
        """添加自定义敏感词"""
        try:
            user_id = str(event.message_obj.sender.user_id)

            if not any(admin_umo.endswith(user_id) for admin_umo in self.admin_qq_list):
                yield event.plain_result("仅管理员可添加敏感词")
                return

            if not word or not word.strip():
                yield event.plain_result("敏感词不能为空")
                return

            # 更新配置
            words_config = self.config.get("custom_forbidden_words", [])
            if word not in words_config:
                words_config.append(word)
                self.config["custom_forbidden_words"] = words_config
                self.config.save_config()

                # 更新运行时数据
                self.custom_forbidden_words.add(word)
                self.local_check_patterns = self._compile_local_patterns()

                yield event.plain_result(
                    f"✅ 已添加敏感词：{word}\n当前敏感词数量：{len(words_config)}"
                )
            else:
                yield event.plain_result(f"⚠️ 敏感词 '{word}' 已存在")

        except Exception as e:
            logger.error(f"添加敏感词失败：{e}")
            yield event.plain_result(f"❌ 添加失败：{str(e)}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("删除敏感词")
    async def remove_forbidden_word(self, event: AiocqhttpMessageEvent, word: str):
        """删除自定义敏感词"""
        try:
            user_id = str(event.message_obj.sender.user_id)

            if not any(admin_umo.endswith(user_id) for admin_umo in self.admin_qq_list):
                yield event.plain_result("仅管理员可删除敏感词")
                return

            words_config = self.config.get("custom_forbidden_words", [])

            if word in words_config:
                words_config.remove(word)
                self.config["custom_forbidden_words"] = words_config
                self.config.save_config()

                # 更新运行时数据
                self.custom_forbidden_words.discard(word)
                self.local_check_patterns = self._compile_local_patterns()

                yield event.plain_result(
                    f"✅ 已删除敏感词：{word}\n剩余敏感词数量：{len(words_config)}"
                )
            else:
                yield event.plain_result(f"❌ 敏感词 '{word}' 不存在")

        except Exception as e:
            logger.error(f"删除敏感词失败：{e}")
            yield event.plain_result(f"❌ 删除失败：{str(e)}")
            
    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("敏感词列表")
    async def list_forbidden_words(self, event: AiocqhttpMessageEvent):
        """查看自定义敏感词列表"""
        try:
            words = list(self.custom_forbidden_words)

            if not words:
                yield event.plain_result("暂无自定义敏感词")
                return

            message = "📋 自定义敏感词列表\n"
            for i, word in enumerate(sorted(words), 1):
                message += f"{i}. {word}\n"

            message += f"\n总计：{len(words)} 个词"

            yield event.plain_result(message)

        except Exception as e:
            logger.error(f"获取敏感词列表失败：{e}")
            yield event.plain_result("获取列表失败")

    @filter.command("敏感词撤回插件状态")
    async def plugin_status(self, event: AiocqhttpMessageEvent):
        """查看插件状态"""
        try:
            status_lines = [
                "🔧 敏感词撤回插件状态",
                f"版本：v0.0.1",
                f"状态：运行中",
                "",
                "⚙️ 核心功能：",
                f"  监控群聊：{len(self.group_whitelist)} 个",
                f"  本地敏感词：{len(self.custom_forbidden_words)} 个",
                f"  本地白名单敏感词：{len(self.custom_white_words)} 个",
                f"  绕过限流：{'是' if self.bypass_rate_limit else '否'}",
                f"  消息撤回：{'启用' if self.enable_message_delete else '禁用'}",
                f"  自动禁言：{'启用' if self.enable_auto_ban else '禁用'}",
                "",
                "📊 统计信息：",
                f"  总检测次数：{self.statistics['total_checks']}",
                f"  检测到敏感词：{self.statistics['sensitive_detected']} 次",
                f"  自动禁言：{self.statistics.get('auto_bans', 0)} 次",
            ]

            yield event.plain_result("\n".join(status_lines))

        except Exception as e:
            logger.error(f"获取插件状态失败：{e}")
            yield event.plain_result("获取状态失败")

    async def terminate(self):
        """插件卸载时的清理工作"""
        logger.info("敏感词撤回插件已卸载")
