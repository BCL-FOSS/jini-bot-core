from quart_auth import AuthUser, Action

class Admin(AuthUser):
    def __init__(self, auth_id=None, action=None):
        super().__init__(auth_id=auth_id, action=action)
        self._user_data = None

    @property
    async def email(self):
        if not self._user_data:
            return self._user_data['eml']
    
    @property
    async def fname(self):
        if not self._user_data:
            return self._user_data['fnm']
    
    @property
    async def lname(self):
        if not self._user_data:
            return self._user_data['lnm']
    
    @property
    async def company(self):
        if not self._user_data:
            return self._user_data['cmp']
    
    @property
    async def uname(self):
        if not self._user_data:
            return self._user_data['unm']