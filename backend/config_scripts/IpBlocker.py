from datetime import datetime
import asyncio
import argparse
from datetime import datetime, timezone
from app import ip_ban_db, logger

async def edit_db(action: str, ip_address: str):
    await ip_ban_db.connect_db()
    match action:
        case 'block':
            now = datetime.now(tz=timezone.utc)
            ban_data = {'ip': ip_address,
                        'banned_at': now.isoformat()}
            if await ip_ban_db.upload_db_data(id=f"blocked_ip:{ip_address}", data=ban_data) > 0:
                logger.info(f"{ip_address} is banned.")

        case 'unblock':
            if await ip_ban_db.del_obj(id=f"blocked_ip:{ip_address}") > 0:
                logger.info(f"{ip_address} is unbanned.")

        case _:
            logger.error("Invalid action. Use 'block' or 'unblock'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modify the IP ban database.")
    parser.add_argument(
        '-a', '--action', 
        type=str, 
        help="Action to perform on the IP ban database (block or unblock)"
    )
    parser.add_argument(
        '-i', '--ip', 
        type=str, 
        help="IP address to act upon"
    )
    args = parser.parse_args()

    asyncio.run(edit_db(args.action, args.ip))