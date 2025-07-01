import pexpect

PROMPT = ['#', '>>>', '>', r'\$']  # Added raw string for regex

def send_command(child, cmd):
    child.sendline(cmd)
    child.expect(PROMPT)
    print(child.before)  # Added parentheses for Python 3

def connect(user, host, password):
    ssh_newkey = 'Are you sure you want to continue connecting?'  # Corrected variable name
    connStr = 'ssh ' + user + '@' + host  # Added missing space
    child = pexpect.spawn(connStr)
    ret = child.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword:'])  # Removed backslash
    
    if ret == 0:  # Colon instead of semicolon
        print('[-] Err Connecting')
        return
    if ret == 1:  # Colon instead of semicolon
        child.sendline('yes')
        ret = child.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword:'])  # Removed backslash
        if ret == 0:  # Colon instead of semicolon
            print('[-] Err Connecting')
            return
    child.sendline(password)
    child.expect(PROMPT)
    return child

def main():  # Added missing colon
    host = 'localhost'
    user = 'root'
    password = 'toor'
    child = connect(user, host, password)
    send_command(child, 'cat /etc/shadow | grep root')

if __name__ == '__main__':
    main()  # Proper indentation