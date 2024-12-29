def create_acl(file_path, user_list):
    acl = {user: {'read': False, 'write': False, 'execute': False} for user in user_list}
    with open(f'{file_path}.acl', 'w') as f:
        f.write(str(acl))

def grant_access(file_path, user, permission):
    with open(f'{file_path}.acl', 'r') as f:
        acl = eval(f.read())
    if user in acl:
        acl[user][permission] = True
    with open(f'{file_path}.acl', 'w') as f:
        f.write(str(acl))