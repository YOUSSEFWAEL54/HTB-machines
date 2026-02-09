# What is Pterodactyl?
![](Images/diagram.png)

It is a game server manager that runs each server in an isolated container.

  *  **Nodes**: The real server (the Host). It can be the same host running the Pterodactyl panel or a separate remote host.

  *  **Wings** (The Agent): The service that lives on the Node to talk to Docker.

  *  **Servers**: These are the Containers (the isolated boxes).

  *  **Eggs**: The "Recipe" or configuration used to build the server (container).

  *  **Yolks**: The actual Docker Image (the OS/environment) inside the server (container).
  

## Pterodactly api Authentication system
Pterodactly uses Bearer Token authentication for all requests. There are two types of API keys depending on which API you're accessing.


# Key Naming Convention
Pterodactyl API keys follow this naming pattern:
    * Client API keys: `ptlc_` followed by the key
    * Application API keys: `ptla_` followed by the key


## client api
Client API keys are created by users for accessing the Client API. These keys have access only to resources that the user creating them has access to.

Where to generate:
  * Navigate to https://your-panel.com/account/api
  * Click "Create API Key"
  * Optionally restrict by IP addresses


## Applicatin api

Application API keys are created by administrators for accessing the Application API. These keys have full administrative access to the panel.

Where to generate:
  * Navigate to https://your-panel.com/admin/api (admin only)
  * Click "Create API Key"
  * Optionally restrict by IP addresses


here is a simple request to the both apis


# Example Requests

## Client API Example

### Get list of servers for the authenticated user
```bash
curl "https://your-panel.com/api/client" \
  -H "Authorization: Bearer ptlc_1234567890abcdef" \
  -H "Content-Type: application/json" \
  -H "Accept: Application/vnd.pterodactyl.v1+json"
```

## Application API Example

### Get list of all users (admin only)
```bash
curl "https://your-panel.com/api/application/users" \
  -H "Authorization: Bearer ptla_1234567890abcdef" \
  -H "Content-Type: application/json" \
  -H "Accept: Application/vnd.pterodactyl.v1+json"
```


you can learn mode details about how api works from this link

https://pterodactyl-api-docs.netvpx.com/docs/intro
