import yara

rules = yara.compile('/home/harishankar/project/rules/malware_index.yar')
#rules_up = yara.compile(file=rules)
#rules.close()clear
matches = rules.match('/home/harishankar/project/mal/CobianRAT_v1.0.40.7/CobianRAT v1.0.40.7.exe')
if(matches==matches):
    print(matches)
    print("[*]It is a virus file ")
else:
    print("{*}It is not a virus fiel")