# umjiniti-core #

Network Monitoring & Agentic Automation platform that leverages open source, locally hosted LLMs to analyze, visualize and troubleshoot on-prem and cloud environments via distributed probes.

<p align="center">
  <img width="300" height="300" src="https://github.com/BCL-FOSS/umjiniti-core/blob/main/backend/static/img/umjinilogo.png?raw=true">
</p>

### About ###


### Get Started ###

1. Generate the OTS_KEY API key with a Basic (free tier) [onetimesecret](https://onetimesecret.com/) account.

2. Generate the BREVO_API_KEY with a Free tier [Brevo CRM and marketing platform](https://www.brevo.com/) account.

3. Complete the following steps for your Brevo CRM account:
  * [Authenticate your domain with Brevo](https://help.brevo.com/hc/en-us/articles/12163873383186-Authenticate-your-domain-with-Brevo-Brevo-code-DKIM-DMARC)
  * [Create a new sender](https://help.brevo.com/hc/en-us/articles/208836149-Create-a-new-sender-From-name-and-From-email#h_01J7K4M7R1ADHZAXN1P35QJVX4)

4. Set the necessary environment variables in the included .env

5. Change the url in the Caddyfile to match SERVER_NAME
```bash
# Caddyfile

umj.baughlabs.tech { # Change this only. Leave everything else the same
  ...
  
```

6. Run the startup script. This installs and configures all necessary dependencies required by umjiniti.
```bash
 sudo ./init.sh
```

6. Generate an account registration key. Securely store this key as this will allow you to create your account within your umjiniti instance. All new users require their own key.

  * Retrieve the container ID for the "umjiniti_core_socket_app" container
```bash
  sudo docker container ls
```
  * Generate your registration key
```bash
  sudo docker exec -it <socket_app_container_id> python /home/quart/registration_key_gen.py -u <YOUR-USERNAME>
```
  * (Optional) Start a shell within the container and run the script if the above command fails
```bash
  sudo docker exec -it <socket_app_container_id> /bin/bash
```

7.  Visit your new umjiniti instance at the SERVER_NAME you set in the .env. Create a new account with the previously generated account registration key.
