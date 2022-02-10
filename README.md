# node-password-hasher

this was created to just hash passwords with an algorithm from the built-in crypto module node.js has

**REQUIRED DEPENDENCIES**

chalk 4.1.2
readline-sync

you can install these with the following command below

node v16.x, v17.x engines
```shell
npm i chalk@4.1.2 | npm i readline-sync
```

node v12 or something else
```shell
npm i chalk@4.1.2 && npm i readline-sync
```
for the ESM version just install the latest version of the chalk module without specifying a version as it's pure esm for v5
and make sure you add the following line to your package.json file for the .mjs one

```json
"type": "module"
```

To run this just clone the repository with git
```shell
git clone https://github.com/PixeledLuaWriter/node-password-hasher.git
cd node-password-hasher
npm i
node /src/node-password-hasher
```
