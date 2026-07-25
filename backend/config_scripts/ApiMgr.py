import os
import uuid
import bcrypt
import secrets
from backend.init_app import logger, util_obj, api_name, cli, utility_scripts_path
from backend.app import cl_auth_db, cl_data_db
import asyncio

async def createapi():
    email_script_path = os.path.join(utility_scripts_path, f'EmailMgr.py')
    if await cl_data_db.get_all_data(match=f"{api_name}:dta:*", cnfrm=True) is False:
        api_id = util_obj.key_gen(size=10) 
        new_api_key = str(uuid.uuid4())
        updated_api_data = {
                api_name: bcrypt.hashpw(new_api_key, bcrypt.gensalt()),
                f"{api_name}_id": api_id,
                f"{api_name}_rand": secrets.token_urlsafe(500),
                f"{api_name}_jwt_secret": secrets.token_urlsafe(500)
        }
        
        if await cl_data_db.upload_db_data(id=f"{api_name}:dta:{api_id}", data=updated_api_data) > 0:
            link = cli.create_link(secret=new_api_key, ttl=int(os.environ.get('OTS_TTL')))
            if await cl_auth_db.get_all_data(match='*pct:*', cnfrm=True) is False:
                logger.info("no primary contact. create an initial user")
                exit()
            prim_contact = await cl_auth_db.get_all_data(match='*pct:*')
            prim_contact_dict = next(iter(prim_contact.values()))
            html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                            <p>Hello,</p>
                            <p>A new <strong>umjiniti</strong> API key has been generated for <strong>{prim_contact_dict.get('email')}</strong>.</p>
                            <p>You can retrieve the API key using the following one-time secret link. Note that this link will expire after a single use.</p>
                            <p>API Key Retrieval Link: <a href="{link}">{link}</a></p>
                            <p>Thank you,<br/>umjiniti Team</p>

                            </div>"""
        
            email_params = {'sender': {'name': 'umjiniti Admin', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                            'to': [{"name": f'{prim_contact_dict.get('fname')} {prim_contact_dict.get('lname')}', "email": prim_contact_dict.get('email')}],
                            'subject': f"New Jini API Key Generated for {prim_contact_dict.get('email')}",
                            'hmtl_content': html_snippet }

            email_command = f"python3 {email_script_path} -t 'send' -p {email_params}"
            email_code, email_output, email_error = -await util_obj.run_shell_cmd(cmd=email_command)
            logger.info(f"code: {email_code}\noutput: {email_output}\nerror: {email_error}")       
            return
        else:
            logger.info('API creation failed')
            return
    else:
        return
if __name__ == "__main__":
    asyncio.run(createapi())
    