global test: table[addr] of set[string];
global ip:addr;

event http_header(c:connection,is_orig:bool,name:string,value:string)
{
 ip=c$id$orig_h;
 if (c$http?$user_agent)
 {
	if(ip !in test)
	{
	test[ip]=set(to_lower(c$http$user_agent));
	}
	else
	{
	add test[ip][to_lower(c$http$user_agent)];
	}
 }
}

event zeek_done()
{
for(m in test)
{
if (|test[m]|>=3)
{
print fmt("%s is a proxy",m);
}
}
}
