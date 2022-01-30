# JWT Deny List Demo

1. Copy `sample.env` to `.env`.
2. Run `npm install`
3. Run `npm start`
4. Hit `/createUser` endpoint to generate JWT
5. Visit `/` to test authentication, with `--header 'Authorization: Bearer <JWT>`
6. Visit `/logout` to add the JWT to the deny list
7. Re-test by visiting `/`
