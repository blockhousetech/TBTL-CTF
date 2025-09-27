# Upload Docs

## Description

We’ve come across a rather unusual solution for uploading documentation, and
I’ve noticed several odd things about it.

Here’s what I know so far:

There’s an `/admin?target_user={user_id}` endpoint that simulates what an admin
would see on the site. From there, the admin can view `target_user` the links.

There’s also a `/get_flag` endpoint, which appears to work only within the
local network.

Local port is `5000`.

[https://fortid-upload-docs.chals.io/](https://fortid-upload-docs.chals.io/)j

## Solution

[link](./solution/README.md)
