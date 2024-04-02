

---@type DP
local dp = _DP
---@type DPXGame
local dpx = _DPX

local game = require("df.game")
local logger = require("df.logger")

local item_handler = { }

--[[
自动完成符合等级的主线任务
仿照7576新建一个道具, 删除[string data]节, 以实现一个可以在城镇中使用后毫无效果的道具
假设道具ID为123005
]]
---@param user CUser
item_handler[10000542] = function(user, item_id)
    local quest = dpx.quest
    local lst = quest.all(user.cptr)
    local chr_level = user:GetCharacLevel()
    for i, v in ipairs(lst) do
        local id = v
        local info = quest.info(user.cptr, id)
        if info then
            if not info.is_cleared and info.type == game.QuestType.epic  and info.min_level <= chr_level - 1 then
                quest.clear(user.cptr, id)
            end
        end
    end
    quest.update(user.cptr)
end


--[[
升级券
仿照7576新建一个道具, 删除[string data]节, 以实现一个可以在城镇中使用后毫无效果的道具
假设道具ID为123008
使用此道具后, 等级提升1级
]]
---@param user CUser
item_handler[10000543] = function(user, item_id)
    user:SetCharacLevel(70)
end

---@param user CUser
item_handler[10000551] = function (user, item_id)
    user:ChargeCeraPoint(500)
    user:SendNotiPacketMessage('500 代币券充值成功')
end

---@param user CUser
item_handler[10000552] = function (user, item_id)
    user:ChargeCeraPoint(1000)
    user:SendNotiPacketMessage('500 代币券充值成功')
end

local _M = {}

function _M:run(_user, item_id)
    local user = game.fac.user(_user)
    local handler = item_handler[item_id]
    if handler then
        handler(user, item_id)
        logger.info("[useitem] acc: %d chr: %d item_id: %d", user:GetAccId(), user:GetCharacNo(), item_id)
    end
end

return _M



