import argparse
import asyncio
from backend.app import util_obj, logger, cl_auth_db
from backend.init_app import utility_scripts_path
import bcrypt
import os

email_script_path = os.path.join(utility_scripts_path, f'EmailMgr.py')

async def register_user(username: str, password: str, telegram_id: int, fname: str, lname: str, email: str) -> None:
    username = username.replace(" ", "").lower()
    password_hash = bcrypt.hashpw(password, bcrypt.gensalt())
    logger.info(f"Registering user: {username}")
    user_nmp, user_id = util_obj.gen_user(username=username)
    user_obj = {
        "id": user_id,
        "unm": username,
        "pwd": password_hash,
        "eml": email,
        "telegram_id": telegram_id,
        "fname": fname,
        "lname": lname
    }
    user_key = f"{user_nmp}:{user_id}"
    
    if await cl_auth_db.get_all_data(match="*pct:*", cnfrm=True) is False:
        user_obj["db_id"] = f'pct:{user_key}'
    else:
        user_obj["db_id"] = user_key

    if await cl_auth_db.upload_db_data(id=user_obj['db_id'], data=user_obj) > 0:
        logger.info(f"Registration successful for '{username}'.")
        if await cl_auth_db.upload_db_data(id=f"telegram_dta:{telegram_id}", data={"id": str(telegram_id)}) > 0:
            logger.info(f"Telegram ID {telegram_id} linked to user '{username}'.")

            contact_data = {"LASTNAME": lname,
                            "FIRSTNAME": fname,
                            }
            add_contact_params = {'email': email,
                        'ext_id': user_obj['db_id'],
                        'attributes': contact_data
                    }
                                
            add_contact_command = f"python3 {email_script_path} -t 'add' -p {add_contact_params}"
            add_contact_code, add_contact_output, add_contact_error = await util_obj.run_shell_cmd(cmd=add_contact_command)
            logger.info(f"code: {add_contact_code}\noutput: {add_contact_output}\nerror: {add_contact_error}")
            return
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Register a new user account from the command line."
    )
    parser.add_argument("-u", "--username", required=True,  help="Desired username")
    parser.add_argument("-p", "--password", required=True,  help="Account password")
    parser.add_argument("-e", "--email", required=True, help="Contact email")
    parser.add_argument("-c", "--chat_telegram_id", required=True, help="Telegram ID")
    parser.add_argument("-fnm", "--fname", required=True, help="User's first name")
    parser.add_argument("-lnm", "--lname", required=True, help="User's last name")
    args = parser.parse_args()
    asyncio.run(register_user(
                username=args.username,
                password=args.password,
                telegram_id=args.telegram_id
            ))