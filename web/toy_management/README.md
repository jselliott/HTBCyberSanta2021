# Web :: Gadget Santa

*The evil elves have changed the admin access to Santa's Toy Management Portal. Can you get the access back and save the Christmas?*

### Challenge Files: [web_toy_management.zip](web_toy_management.zip)

For this challenge, there is a docker component that hosts the vulnerable website, but you are provided with the challenge files to develop an exploit.

On this site, I neglected to take a screenshot of, you are presented with a login page which is used to access the toy management interface. Looking at the code for the login function, you can see that it is wide open to SQL Injection.

```js
async loginUser(user, pass) {
		return new Promise(async (resolve, reject) => {
			let stmt = `SELECT username FROM users WHERE username = '${user}' and password = '${pass}'`;
			this.connection.query(stmt, (err, result) => {
				if(err)
					reject(err)
				try {
					resolve(JSON.parse(JSON.stringify(result)))
				}
				catch (e) {
					reject(e)
				}
			})
		});
	}
```

On the login page we can simply enter `' OR 1=1#` to get logged into the site. However, it doesn't seem to show anything out of the ordinary except for a list of toys.

So let's check the code for that page...

```js 
router.get('/api/toylist', AuthMiddleware, async (req, res) => {
	return db.getUser(req.data.username)
		.then(user => {
			approved = 1;
			if (user[0].username == 'admin') approved = 0;
			return db.listToys(approved)
				.then(toyInfo => {
					return res.json(toyInfo);
				})
				.catch(() => res.status(500).send(response('Something went wrong!')));
		})
		.catch(() => res.status(500).send(response('Something went wrong!')));
});
```

Here we can see that if the user is admin, then they can also see unapproved toys. So after we go back to the login page, we can put in a ```admin' or 1=1#``` in the username field and anything in the password field. And we are able to login and see the flag.

(Sadly I didn't copy it down >.<)