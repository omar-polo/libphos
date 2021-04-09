local phos = require('phos')

local client = phos:new_client()
client:req('localhost', '1996', 'gemini://localhost/\r\n')

client:handshake_sync()
if client:response_sync() == -1 then
   error(client:err())
end

local code, meta = client:res();
print(string.format('code=%d meta=%s', code, meta))

while true do
   local buf, l = client:read_sync()
   if l == 0 then
      break
   elseif l == -1 then
      error(client:err())
   else
      print(buf)
   end
end

client:close_sync()
