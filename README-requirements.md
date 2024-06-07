
### Functional Requirements

- Users can login
- Authenticated users can create rooms
- Created rooms are owned by their creator
- Room owners can invite other users
- Authenticated users can chat in any room they create or are invited to
- Users can delete their own messages
- Owners can delete messages in rooms they own
- Owners can delete rooms they create

### Security Requirements

- Non-authenticated users cannot chat or create rooms
- Users cannot delete rooms they don't own
- Users cannot delete other users' messages (unless the user was the one who created the room)
- No user can cause chat performance problems for other users
- No user can see any other user's password
- Rooms can only be deleted by their owner
- No user can deny allowed users access the parts of the service they have permission to

### Aspects of security that will be directly enforced with code

- No user can cause chat performance problems for other users
- No user can deny allowed users access the parts of the service they have permission to

### Aspects of security that will be enforced by the containing operating system

- Non-authenticated users cannot chat or create rooms
- Users cannot delete rooms they don't own
- Users cannot delete other users' messages (unless the user was the one who created the room)
- No user can cause chat performance problems for other users
- Rooms can only be deleted by their owner

