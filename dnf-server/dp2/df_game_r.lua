---@type DP
local dp = _DP
---@type DPXGame
local dpx = _DPX

local luv = require("luv")
local game = require("df.game")
local logger = require("df.logger")

logger.info("opt: %s", dpx.opt())
-- see dp2/lua/df/doc for more information !


--enable frida framework
local frida = require("df.frida")
frida.load()


-- -- 记录在线账号
-- local online = {}

-- local function onLogin(_user)
--     local user = game.fac.user(_user)
--     local uid = user:GetAccId()
--     logger.info(user:GetCharacName(), " 登录了")

--     online[uid] = true
-- end
-- dpx.hook(game.HookType.Reach_GameWord, onLogin)

-- local function onLogout(_user)
--     local user = game.fac.user(_user)
--     local uid = user:GetAccId()
--     online[uid] = nil
-- end
-- dpx.hook(game.HookType.Leave_GameWord, onLogout)


-- -- 玩家指令监听
-- local on_input = function(fnext, _user, input)
--     local key = "ext.gmInput";
--     local gmInput = require(key)
--     gmInput:run(_user, input)
--     return fnext()
-- end
-- dpx.hook(game.HookType.GmInput, on_input)


-- -- 监听副本掉落事件
-- local drop_item = function(_party, monster_id)
--     local key = "ext.partyDropItem";
--     local partyDropItem = require(key)
--     return partyDropItem:run(_party, monster_id, online)
-- end
-- dpx.hook(game.HookType.CParty_DropItem, drop_item)


-- -- 监听游戏事件
-- local game_event = function(fnext, type, _party, param)
--     local key = "ext.gameEvent";
--     local partyDropItem = require(key)
--     partyDropItem:run(type, _party, param, online)
--     return fnext()
-- end
-- dpx.hook(game.HookType.GameEvent, game_event)


-- 监听物品事件
local stack_event = function(user, item_id)
    local key = "ext.stack";
    local partyDropItem = require(key)
    partyDropItem:run(user, item_id)
end
dpx.hook(game.HookType.UseItem2, stack_event)

dpx.enable_creator()
dpx.open_timegate()
dpx.set_unlimit_towerofdespair()


logger.info('dp2 start success')
