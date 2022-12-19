--[[
    lua wireshark addon for the UMAS embeded modbus protocol 
    made by biero-el-corridor
--]]

-- functions that made the concordance of the umas_code -> funtions meaning
function get_umas_function_name(code)
    local code_name = "Unknow"
    -- source: http://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-i.html
    if code == 1 then code_name = "0x01 - INIT_COMM: Initialize a UMAS communication"
    elseif code == 2 then code_name = "0x02 - READ_ID: Request a PLC ID"
    elseif code == 3 then code_name = "0x03 - READ_PROJECT_INFO: Read Project Information"
    elseif code == 4 then code_name = "0x04 - READ_PLC_INFO: Get internal PLC Info"
    elseif code == 6 then code_name = "0x06 - READ_CARD_INFO: Get internal PLC SD-Card Info"
    elseif code == 10 then code_name = "0x0A - REPEAT: Sends back data sent to the PLC (used for synchronization)"
    elseif code == 16 then code_name = "0x10 - TAKE_PLC_RESERVATION: Assign an owner to the PLC"
    elseif code == 17 then code_name = "0x11 - RELEASE_PLC_RESERVATION: Release the reservation of a PLC"
    elseif code == 18 then code_name = "0x12 - KEEP_ALIVE: Keep alive message (???)"
    elseif code == 32 then code_name = "0x20 - READ_MEMORY_BLOCK: Read a memory block of the PLC"
    elseif code == 34 then code_name = "0x22 - READ_VARIABLES: Read System bits, System Words and Strategy variables"
    elseif code == 35 then code_name = "0x23 - WRITE_VARIABLES: Write System bits, System Words and Strategy variables"
    elseif code == 36 then code_name = "0x24 - READ_COILS_REGISTERS: Read coils and holding registers from PLC"
    elseif code == 37 then code_name = "0x25 - WRITE_COILS_REGISTERS: Write coils and holding registers into PLC"
    elseif code == 48 then code_name = "0x30 - INITIALIZE_UPLOAD: Initialize Strategy upload (copy from engineering PC to PLC)"
    elseif code == 49 then code_name = "0x31 - UPLOAD_BLOCK: Upload (copy from engineering PC to PLC) a strategy block to the PLC"
    elseif code == 50 then code_name = "0x32 - END_STRATEGY_UPLOAD: Finish strategy Upload (copy from engineering PC to PLC)"
    elseif code == 51 then code_name = "0x33 - INITIALIZE_UPLOAD: Initialize Strategy download (copy from PLC to engineering PC)"
    elseif code == 52 then code_name = "0x34 - DOWNLOAD_BLOCK: Download (copy from PLC to engineering PC) a strategy block"
    elseif code == 53 then code_name = "0x35 - END_STRATEGY_DOWNLOAD: Finish strategy Download (copy from PLC to engineering PC)"
    elseif code == 57 then code_name = "0x39 - READ_ETH_MASTER_DATA: Read Ethernet Master Data"
    elseif code == 58 then code_name = "0x40 - START_PLC: Starts the PLC"
    elseif code == 59 then code_name = "0x41 - STOP_PLC: Stops the PLC"
    elseif code == 80 then code_name = "0x50 - MONITOR_PLC: Monitors variables, Systems bits and words"
    elseif code == 88 then code_name = "0x58 - CHECK_PLC: Check PLC Connection status"
    elseif code == 112 then code_name = "0x70 - READ_IO_OBJECT: Read IO Object"
    elseif code == 113 then code_name = "0x71 - WRITE_IO_OBJECT: WriteIO Object"
    elseif code == 115 then code_name = "0x73 - GET_STATUS_MODULE: Get Status Module"
    elseif code == 254 then code_name = "0xfe - Response Meaning OK"
    elseif code == 253 then code_name = "0xfd - Response Meaning Error" end
    return code_name
end

modbus1_protocol = Proto("Modbus1", "Modbus .")
umas_protocol = Proto("UMAS", "UMAS .")

-- ressourc that worth your time https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html
----------- part of the modbus protocol ---------------
Transaction_Identifier  = ProtoField.uint16("Modbus1.Transaction_Identifier"  , "Transaction_Identifier"  , base.DEC)
Protocol_Identifier     = ProtoField.uint16("Modbus1.Protocol_Identifier"     , "Protocol_Identifier"     , base.DEC)
Length                  = ProtoField.uint16("Modbus1.Length"                  , "Length"                  , base.DEC)
Unit_Identifier         = ProtoField.int8("Modbus1.Unit_Identifier"         , "Unit_Identifier"         , base.DEC)
modbus1_protocol.fields = { Transaction_Identifier, Protocol_Identifier, Length, Unit_Identifier }
-------------------------------------------------------

----------- part of the UMAS protocol -----------------
Function_Code           = ProtoField.uint8("UMAS.Function_Code"         , "Function_Code"        , base.HEX_DEC)
Pairing_Key             = ProtoField.uint8("UMAS.Pairing_Key"           , "Pairing_Key"          , base.HEX)
Umas_Functions_Code     = ProtoField.uint8("UMAS.Umas_Functions_Code"   , "Umas_Functions_Code"  , base.DEC)
Umas_Data               = ProtoField.string("UMAS.Umas_Data"            , "Umas_Data"            , base.ASCII )
umas_protocol.fields    = { Function_Code, Pairing_Key, Functions_Code , Umas_Functions_Code ,Umas_Data }
-------------------------------------------------------

function modbus1_protocol.dissector(buffer,pinfo,tree)
    -- get the size of the packet sections 
    length = buffer:len()

    ------------------------------------------
    -- BEGIN OF THE MODBUS SECTIONS ----------
    ------------------------------------------

    -- if the sections is empty , terminate the process
    if length == 0 then return end
    
    -- apply the name in the column if the protocol is detected
    pinfo.cols.protocol = modbus1_protocol.name

    -- add the layer umas in the list of potential layer 
    local subtree       = tree:add(modbus1_protocol, buffer()      , "Modbus Protocol Data")
    local modbusSubtree = subtree:add(modbus1_protocol, buffer()   ,"modbus header")

    modbusSubtree:add(Transaction_Identifier   ,buffer(0,2))
    modbusSubtree:add(Protocol_Identifier      ,buffer(2,2))
    modbusSubtree:add(Length                   ,buffer(4,2))
    modbusSubtree:add(Unit_Identifier          ,buffer(6,1))
    ------------------------------------------
    -- END OF THE MODBUS SECTIONS ------------
    ------------------------------------------
    
    ------------------------------------------
    -- BEGIN OF THE UMAS SECTIONS ------------
    ------------------------------------------

    local umas_identifier = buffer(7,1):le_uint()
    local umas_code = buffer(9,1):le_uint()
    local umas_code_name = get_umas_function_name(umas_code)

    local getData = buffer(10)
    local data = getData:le_ustring()

    if(umas_identifier == 90) 
    then
        local data_length = length - 10
        local umasSubtree   = subtree:add(modbus1_protocol ,buffer()   ,"umas")
        umasSubtree:add(Function_Code, buffer(7,1))
        umasSubtree:add(Pairing_Key, buffer(8,1))
        umasSubtree:add(Umas_Functions_Code,buffer(9,1)):append_text(" (" .. umas_code_name .. ")")
        umasSubtree:add(Umas_Data, getData, data)
    end
    ------------------------------------------
    -- END OF THE UMAS SECTIONS ------------
    ------------------------------------------ 
end

-- subtree for the definitions of the UMAS protocol. 
function umas_protocol.dissector(buffer,pinfo,tree)
    length = buffer:len()
    if length == 0 then return end
    pinfo.cols.protocol = umas_protocol.name

    local subtree = tree:add(umas_protocol, buffer, "UMAS")
    subtree:add_le(Function_Code, buffer(7,1))
end

local modbus = DissectorTable.get("tcp.port")
modbus:add(502, modbus1_protocol)

