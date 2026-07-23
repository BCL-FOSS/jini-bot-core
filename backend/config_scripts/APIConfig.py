from onetimesecret import OneTimeSecretCli
from backend.utils.EmailSenderHandler import EmailSenderHandler
import os
import uuid
from passlib.hash import bcrypt
import secrets
from app import logger, util_obj, cl_data_db, api_name
import argparse
import asyncio

email_sender_handler = EmailSenderHandler(brevo_api_key=os.environ.get('BREVO_API_KEY'))
cli = OneTimeSecretCli(os.environ.get('OTS_USER'), os.environ.get('OTS_KEY'), os.environ.get('REGION'))

async def resetapi(email: str, current_api: str):
    old_api_data = await cl_data_db.get_all_data(match=f"{api_name}:dta:*")
    old_api_data_dict = next(iter(old_api_data.values())) if old_api_data else None
    if await cl_data_db.del_obj(key=f"{api_name}:dta:{old_api_data_dict.get(f'{api_name}_id')}") is not None:
        api_id = util_obj.key_gen(size=10) 
        new_api_key = str(uuid.uuid4())
        updated_api_data = {
            api_name: bcrypt.hash(new_api_key),
            f"{api_name}_id": api_id,
            f"{api_name}_rand": secrets.token_urlsafe(500),
            f"{api_name}_jwt_secret": secrets.token_urlsafe(500)
        }
   
        if await cl_data_db.upload_db_data(id=f"{api_name}:dta:{api_id}", data=updated_api_data) > 0:
            link = cli.create_link(secret=new_api_key, ttl=int(os.environ.get('OTS_TTL')))

            html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                        <p>Hello,</p>
                        <p><strong>umjiniti</strong> API key for 'JiniBot <strong>{os.getenv('JINIBOT_NAME')}</strong> has been reset.</p>
                        <p>You can retrieve the API key using the following one-time secret link. Note that this link will expire after a single use.</p>
                        <p>API Key Retrieval Link: <a href="{link}">{link}</a></p>
                        <p>Thank you,<br/>umjiniti Team</p>

                        </div>"""
            send_result = email_sender_handler.send_transactional_email(sender={'name': 'umjiniti Admin', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                                                                 to=[{"name": email, "email": email}],
                                                                                 subject=f"umjiniti-core API Key Reset for {os.getenv('JINIBOT_NAME')}",
                                                                                 html_content=html_snippet
                                                                                 )
            logger.info(f"API key reset email send result: {send_result}")
    else:
        logger.info('API reset failed')
    
        
async def createapi(fname: str, lname: str, email: str):
    api_name = os.environ.get('API_NAME')
    if await cl_data_db.get_all_data(match=f"{api_name}:dta:*", cnfrm=True) is False:
        api_id = util_obj.key_gen(size=10) 
        new_api_key = str(uuid.uuid4())
        updated_api_data = {
                api_name: bcrypt.hash(new_api_key),
                f"{api_name}_id": api_id,
                f"{api_name}_rand": secrets.token_urlsafe(500),
                f"{api_name}_jwt_secret": secrets.token_urlsafe(500)
        }
            
        if await cl_data_db.upload_db_data(id=f"{api_name}:dta:{api_id}", data=updated_api_data) > 0:
            link = cli.create_link(secret=new_api_key, ttl=int(os.environ.get('OTS_TTL')))
            contact_data = {"LASTNAME": lname,
                                    "FIRSTNAME": fname,
                                    }
            new_contact_result = email_sender_handler.add_contact(email=email,
                        ext_id=email, attributes=contact_data
            )
            logger.info(type(new_contact_result))
            logger.info(f"New contact creation result: {new_contact_result}")

            if not new_contact_result:
                logger.error(f"Failed to create contact in Brevo for email {email}. API key creation aborted.")
                return
            
            if await cl_data_db.get_all_data(match="*primary-contact-email*", cnfrm=True) is False:
                email_upload_result = await cl_data_db.upload_db_data(id=f'primary-contact-email', data={'email': email})
                logger.info(f"was the email uploaded?: {email_upload_result}")
                    
            html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                            <p>Hello,</p>
                            <p>A new <strong>umjiniti</strong> API key has been generated for <strong>{email}</strong>.</p>
                            <p>You can retrieve the API key using the following one-time secret link. Note that this link will expire after a single use.</p>
                            <p>API Key Retrieval Link: <a href="{link}">{link}</a></p>
                            <p>Thank you,<br/>umjiniti Team</p>

                            </div>"""
            send_result = email_sender_handler.send_transactional_email(
                sender={'name': 'umjiniti Admin', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                to=[{"name": email, "email": email}],
                subject=f"New umjiniti-core API Key Generated for {email}",
                html_content=html_snippet
            )

            logger.info(type(send_result))
            logger.info(f"API key creation email send result: {send_result}")       
            return
        else:
            logger.info('API creation failed')
            return
    else:
        return
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Register a new user account from the command line."
    )
    parser.add_argument("-n", "--new", required=True,  help="Desired username")
    parser.add_argument("-r", "--reset", required=True,  help="Account password")
    parser.add_argument("-e", "--email",    required=True,  help="Email address")
    parser.add_argument("-f", "--fname",    required=False,  help="First name")
    parser.add_argument("-l", "--lname",    required=False,  help="Last name")
    args = parser.parse_args()

    if args.new:
        asyncio.run(createapi(
            fname=args.fname,
            lname=args.lname,
            email=args.email
        ))

    if args.reset:
        asyncio.run(resetapi(
            email=args.email
        ))