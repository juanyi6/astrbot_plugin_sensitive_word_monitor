# 敏感词撤回插件
监测群聊的发言的合规，管理员权限可阶梯式禁言，下载即用  
支持白名单控制 支持配置管理员私信提示 支持自定义敏感词 支持API远程检测 支持白名单  
# 主要功能
自动监控 - 自动检测群消息中的敏感词  
智能检测 - 支持本地检查和远程API检查双引擎  
自动处理 - 自动删除违规消息、自动禁言违规用户  
分级禁言 - 根据违规次数自动提级禁言（60秒→10分钟→1天）  
数据缓存 - 消息内容缓存，减少API调用  
频率限制 - API调用频率限制器，防止过度调用  
数据库记录 - 记录所有违规信息，支持数据分析  
统计分析 - 详细的违规统计和数据报告  
# 配置项
group_whitelist	监控的白名单群聊  
admin_qq_list	管理员QQ列表  
api_endpoint_enable 是否在开启API检测功能  
api_endpoint	敏感词检查API地址  
enable_auto_ban	是否启用自动禁言  
enable_message_delete	是否启用自动删除消息  
enable_local_check	是否启用本地检查  
debug_mode	是否启用调试模式  
cooldown_seconds	用户查询冷却时间  
max_log_days	违规记录保留天数  
cache_ttl	缓存过期时间（秒）  
max_cache_size	最大缓存条目数  
max_retries	最大重试次数  
first_ban_duration	首次禁言时长（秒）  
second_ban_duration	第二次禁言时长（秒）  
third_ban_duration	第三次禁言时长（秒）  
custom_white_words 自定义白名单词列表  
custom_forbidden_words 自定义违禁词列表  
# 感谢
本插件是在[敏感词监控插件（优化修复版）](https://github.com/YiChex/astrbot_plugin_CNKD_Admin)的基础上二次开发而来  
并且已经得到了原作者的授权，感谢YiChex  
# 反馈渠道
GitHub Issues：https://github.com/juanyi6/astrbot_plugin_sensitive_word_monitor  
QQ 反馈群：714496433  
如果 敏感词撤回插件 帮你挡下了一次广告入侵，别忘了给仓库点个 ⭐️ 支持！
