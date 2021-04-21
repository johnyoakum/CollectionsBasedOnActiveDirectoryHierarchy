# Create Collections Based On Active Directory Hierarchy

I wanted to find a way to in essence mimic my Active Directory Structure within MEMCM with Collecions including the OU/Folder structure.

I wrote this script as an easier and repeatable way to create that structure and maintain it, flexible enough to handle any AD structure.

This will create a folder in a root folder you specify in MEMCM for each OU that you based on the starting point. It will also create a collection within that folder that will contain the any computer that is in those OUs (base plus nested) from that folder.

It will create the folder, create the collection, create the collection membersip rule and then update the membership and move the collection into the corresponding folder.

It is a work in progress, but I haven't found anything else out there that can do all of it easily.

I hope anyone who finds this likes it.
