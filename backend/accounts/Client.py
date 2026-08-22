from quart_auth import AuthUser, Action

class Client(AuthUser):
    def __init__(self, auth_id=None, action=None):
        super().__init__(auth_id=auth_id, action=action)
        self._netsumap_subscription=None
        self._omada_subscription=None
        self._ubnt_subscription=None
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

    @property
    async def netsumap(self):
        return self._netsumap_subscription
    
    @netsumap.setter
    async def set_netsumap(self, value):
        self._netsumap_subscription=value

    @property
    async def omada(self):
        return self._omada_subscription
    
    @omada.setter
    async def set_omada(self, value):
        self._omada_subscription=value

    @property
    async def ubnt(self):
        return self._ubnt_subscription
    
    @ubnt.setter
    async def set_ubnt(self, value):
        self._ubnt_subscription=value

    


