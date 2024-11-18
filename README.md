# NIER

## Dependencies
`lighttpd, apache-utils(specifically htpasswd), fcgi, fcgi-devel, mosquitto`

## Setup
1. Clone repository into home folder - `git clone https://github.com/char-array-theocracy/NIER`
2. Install dependencies
3. [Create users](#user-creation)
4. Run server using `./scripts/start_server.sh`
## User creation
- User data is stored in `config/.htpasswd`. 
- **User passwords are stored as hashes!**
- To manually create a new user you use `htpasswd -c /home/$USER/NIER/config/.htpasswd username`, it will prompt you for a password once command is run. **You might need to use elevated permissions**.