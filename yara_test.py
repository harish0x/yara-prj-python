import yara

rules = yara.compile('/home/harishankar/rules/index.yar')
#rules_up = yara.compile(file=rules)
#rules.close()clear
matches = rules.match('/home/harishankar/v2/scanfile/d257cfde7599f4e20ee08a62053e6b3b936c87d373e6805f0e0c65f1d39ec320')
if(matches):
    print(matches)
    print("[*]It is a virus file ")
else:
    print("{*}It is not a virus fiel")