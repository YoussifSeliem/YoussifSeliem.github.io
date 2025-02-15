---
title: "Kerberos Delegation"
tags:
    - active directory
date: "2024-07-15"
thumbnail: "/assets/img/thumbnail/kerberos.png"
bookmark: true
---

Delegation means to delegate someone A to do specific task instead of someone B using the privilages of B

# Kerberos Unconstrained Delegation

It's allowing the first hop server (can be web server as example) to request access to any resource in the domain.
<img src="/assets/img/active dir/capture2.jpg" alt="unconstrained delegation">
Before we go consider this situation ..
You have an application server (has unconstrained delegation) and you as a user can access it
There's also server B which can't be accessed by the user directly (The user has the privilages of accessing it but not through a direct interface), The app server can access the server B through an interface beteen them

So if you want to access the server B you need to make use of the unconstrained delegation in the application server (Front end) to make it forward your request with your privilages to the Server B (Backend server).

In This image we can see the operation
- In the steps 1,2 the user requests TGT for authentication as known before
- In the steps 3,4 the user requests TGS to access the app server (the point of unconstrained delegation)
    - This TGS will contain also a forwardable TGT of the user
    - The server can use the TGT embedded in the TGS to request the TGS of server B as example
    - and it will get a valid TGS to access the server B because it's based on the user's privilages



## Attack

The attack involves determining The components that has unconstrained delegation, then dumping the tickets it save so may lead us to impersonate the owners of the tickets