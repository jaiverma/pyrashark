pyra = Proto("pyra", "Pyra")

local f = pyra.fields

local types = {"Text", "File"}

f.length = ProtoField.uint32("pyra.length", "Length")
f.data_type = ProtoField.uint32("pyra.data_type", "Data Type", nil, types)
f.data = ProtoField.bytes("pyra.data", "Data")
f.decoded = ProtoField.string("pyra.decoded", "Decoded Data")

function get_len(buffer, info, offset)
    local length = buffer(offset, 4):le_uint() + 8
    return length
end

function do_dissection(buffer, pinfo, tree)
    pinfo.cols.protocol = "Pyra"

    local length = buffer(0, 4):le_uint()
    local data_type = buffer(4, 4):le_uint() + 1
    local data = buffer(8)
    local decoded = buffer(8):string()

    local subtree = tree:add(pyra, buffer())

    subtree:add(f.length, length)
    subtree:add(f.data_type, data_type)
    subtree:add(f.data, data)
    subtree:add(f.decoded, decoded)
end


function pyra.dissector(buffer, pinfo, tree)
    dissect_tcp_pdus(buffer, tree, 4, get_len, do_dissection)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(9999, pyra)
