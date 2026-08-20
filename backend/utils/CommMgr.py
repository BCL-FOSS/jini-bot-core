from backend.init_app import logger, utility_scripts_path, util_obj
from backend.app import cl_data_db
import os
from datetime import datetime, timezone
import uuid
class CommMgr:
    def __init__(self):
        pass

    async def send_llm_response(self, alerts: list, flow_name: str, prompt:str, llm_resp: str, task_output: str):
        now = str(datetime.now(tz=timezone.utc))
        for alert in alerts:
            match alert:
                case 'email':
                    email_contact = await cl_data_db.get_all_data(match='*pct:*')
                    email_contact_data = next(iter(email_contact.values()))
        
                    html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                                                            <p>Jini Monitor Analysis Complete</p>
                                                            <p>Workflow: {flow_name}</p>
                                                            <p>Prompt: {prompt}</p>
                                                            <p>Response: {llm_resp}</p>
                                                            <p>Tool(s) Output: {task_output}</p>
                                                            </div>"""
                    email_params = {'sender': {'name': 'jini bot', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                                            'to': [{"name": f'{email_contact_data.get('fname')} {email_contact_data.get('lname')}', "email": email_contact_data.get('eml')}],
                                                            'subject': f'jini Bot Analysis Report - {flow_name} - {now}',
                                                            'html_content': html_snippet}
                    email_script_path = os.path.join(utility_scripts_path, f'EmailMgr.py')
                    email_command = f"python3 {email_script_path} -t 'send' -p {email_params}"
                    email_code, email_output, email_error = await util_obj.run_shell_cmd(cmd=email_command)
                    logger.info(f'code: {email_code}\noutput: {email_output}\nerror: {email_error}')
                case 'jira':
                    jira_script_path = os.path.join(utility_scripts_path, 'JiraMgr.py')
                    jira_params = {'message': llm_resp}
                    jira_command = f"python3 {jira_script_path} -t 'alert' -p {jira_params}"
                    jira_code, jira_output, jira_error = await util_obj.run_shell_cmd(cmd=jira_command)
                case 'slack':
                    slack_script_path = os.path.join(utility_scripts_path, 'SlackMgr.py')
                    slack_params = {}
                    slack_command = f"python3 {slack_script_path} -t 'alert' -p {slack_params}"
                    slack_code, slack_output, slack_error = await util_obj.run_shell_cmd(cmd=slack_command)
        
        anlys_id = f'anlys:{flow_name}:{now}:{str(uuid.uuid4())}'
        anlys_data = {'id': anlys_id,
            'flow_name': flow_name,
            'prompt': prompt,
            'llm_resp': llm_resp,
            'task_output': task_output
        }
        if await cl_data_db.upload_db_data(id=anlys_id, data=anlys_data) > 0:
            logger.info(f'{flow_name} analysis complete')
            return