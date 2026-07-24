import argparse
import asyncio
import json
import sys
from passlib.hash import bcrypt
from init_app import util_obj, logger
from app import cl_auth_db
import os

async def register_user(username: str, password: str, telegram_id: int) -> None:
    username = username.replace(" ", "").lower()
    password_hash = bcrypt.hash(password)
    logger.info(f"Registering user: {username}")
    user_nmp, user_id = util_obj.gen_user(username=username)
    user_obj = {
        "id": user_id,
        "unm": username,
        "pwd": password_hash,
        "telegram_id": telegram_id,
    }
    user_key = f"{user_nmp}:{user_id}"
    user_obj["db_id"] = user_key
    uploaded = await cl_auth_db.upload_db_data(id=user_key, data=user_obj)
    if uploaded > 0:
        logger.info(f"Registration successful for '{username}'.")
        if await cl_auth_db.upload_db_data(id=f"telegram_dta:{telegram_id}", data={"id": str(telegram_id)}) > 0:
            logger.info(f"Telegram ID {telegram_id} linked to user '{username}'.")
    else:
        logger.error(f"DB upload failed for user '{username}'.")

cwd = os.getcwd()
utility_scripts_path = os.path.join(cwd, 'ai', 'utils', 'jini-utils')

async def check_for_utils():
    # Check if jini utility scripts have been downloaded. If not, clones from github.
    if os.path.isdir(utility_scripts_path) is False:
        code, output, error = await util_obj.run_shell_cmd(cmd=f'cd {os.path.join(cwd, 'ai', 'utils')} && git clone https://github.com/BCL-FOSS/jini-utils.git')
        if code != 0:
            logger.info(f'Error: {error}\nOutput: {output}')
            exit(code=code)
        logger.info(output)
    else:
        pass
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Register a new user account from the command line."
    )
    parser.add_argument("-u", "--username", required=True,  help="Desired username")
    parser.add_argument("-p", "--password", required=True,  help="Account password")
    parser.add_argument("-c", "--chat_telegram_id", required=True, help="Telegram ID")
    parser.add_argument("-t", "--task", required=True)
    args = parser.parse_args()

    match args.task:
        case 'c':
            asyncio.run(check_for_utils())
        case 'u':
            asyncio.run(register_user(
                username=args.username,
                password=args.password,
                telegram_id=args.telegram_id
            ))

