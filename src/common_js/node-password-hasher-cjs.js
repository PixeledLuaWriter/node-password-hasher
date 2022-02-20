/*
Copyright (C) 2022  PixeledLuaWriter (Godcat567)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.
*/

/**
 * @author PixeledLuaWriter (Godcat567)
 * @description Allows You To Hash Your Password With a Salt with
 * an optional algorithm
 * @version 3.2.0
**/

/* 
    Dependencies required
    Crypto (Already built into node.js by default),
    readline-sync,
    chalk

    use "npm i readline-sync | npm i chalk to install"
    both modules (if "|" doesn't work with node 12 then use && for node 12.x and lower)
*/

const { createHmac, randomBytes } = require("crypto");
const readlineSync = require("readline-sync");
const chalk = require("chalk");

function genSalt(rounds) {
    if (rounds > 32) {
        throw new Error(`${rounds} is greater than the maximum length, please use a shorter number next time`)
    }
    if (typeof rounds !== 'number') {
        throw new Error(`Rounds parameter must be an integer/number not a(n) ${typeof rounds}`)
    }
    if (rounds == null) {
        rounds = 29
    }
    return randomBytes(Math.ceil(rounds / 2)).toString('hex').slice(0, rounds)
}

function hasher(algorithm, pwrd, salt) {
    let hashed = createHmac(algorithm, salt)
    hashed.update(pwrd);
    let digested = hashed.digest('hex')
    return {
        salt: salt,
        hashed_password: digested
    }
}

function validateHash(algorithm, usrpwrd, hshpwrd, salt) {
    let hashed = createHmac(algorithm, salt)
    hashed.update(usrpwrd)
    usrpwrd = hashed.digest("hex")
    if(usrpwrd == hshpwrd) {
        return "Hash Matches User's Password"
    } else {
        return "Hash or User's Password Doesn't Match"
    }
}

const hash = (algorithm, password, salt) => {
    if (password == null || salt == null || algorithm == null) {
        throw new Error(`Please provide a hashing/ciphering algorithm, a password and a salt string`)
    }
    if (typeof password !== 'string' || typeof salt !== 'string' || typeof algorithm !== 'string') {
        throw new Error(`Algorithm, Password must be strings, salt must be a string or a length number`)
    }
    return hasher(algorithm, password, salt)
}

const ColorLog = (color, output) => {
    console.log(chalk[color](`${output}`))
}

const selection = readlineSync.question(chalk.yellowBright("Do you want to hash and validate an encrypted cipher/hash or do you want to hash a password? (validate or hash)\n"))
if(selection === "hash") {
    if (readlineSync.keyInYN(chalk.yellowBright("Do you wish to use an optional algorithm within this setup?\n"))) {
        const algorithm_list = [
            "RSA-MD5",
            "RSA-SHA1",
            "RSA-SHA1-2",
            "RSA-SHA224",
            "RSA-SHA256",
            "RSA-SHA3-224",
            "RSA-SHA3-256",
            "RSA-SHA3-384",
            "RSA-SHA3-512",
            "RSA-SHA384",
            "RSA-SHA512",
            "RSA-SHA512/224",
            "RSA-SHA512/256",
            "md5",
            "md5-sha1",
            "md5WithRSAEncryption",
            "sha1",
            "sha1WithRSAEncryption",
            "sha224",
            "sha224WithRSAEncryption",
            "sha256",
            "sha256WithRSAEncryption",
            "sha3-224",
            "sha3-256",
            "sha3-384",
            "sha3-512",
            "sha384",
            "sha384WithRSAEncryption",
            "sha512",
            "sha512-224",
            "sha512-224WithRSAEncryption",
            "sha512-256",
            "sha512-256WithRSAEncryption",
            "sha512WithRSAEncryption",
        ]
        const chosen_algorithm = readlineSync.keyInSelect(algorithm_list, 'Choose a Hashing Algorithm')
        const pass = readlineSync.question(chalk.red.italic("Please Input a password to encrypt it\n->"), {
            hideEchoBack: true,
            mask: chalk.rgb(172, 172, 172)("-")
        })
        const salt_length = readlineSync.questionInt(chalk.red.italic("How long do you want your salt string ranging from (1-32)?\n"))
        setTimeout(() => {
            ColorLog("cyan", "Password & Salt")
        }, 0)
        setTimeout(() => {
            let pwrd = hash(algorithm_list[chosen_algorithm], pass, genSalt(salt_length))
            ColorLog("yellowBright", `<============== HASH + SALT ==============>\n Encrypted Password: ${pwrd.hashed_password + pwrd.salt}\n\n`)
        }, 500)
    } else {
        const pass = readlineSync.question(chalk.red.italic("Please Input a password to encrypt it\n->"), {
            hideEchoBack: true,
            mask: chalk.rgb(172, 172, 172)("-")
        })
        const salt_length = readlineSync.questionInt(chalk.red.italic("How long do you want your salt string ranging from (1-32)?\n"))
        setTimeout(() => {
            ColorLog("reset", "\n")
        }, 0)
        setTimeout(() => {
            let pwrd = hash("sha512", pass, genSalt(salt_length))
            ColorLog("yellowBright", `<============== HASH + SALT ==============>\n Encrypted Password: ${pwrd.hashed_password + pwrd.salt}\n\n`)
        }, 500)
    }
} else if(selection === "validate") {
    if (readlineSync.keyInYN(chalk.yellowBright("Do you wish to use an optional algorithm within this setup?\n"))) {
        const algorithm_list = [
            "RSA-MD5",
            "RSA-SHA1",
            "RSA-SHA1-2",
            "RSA-SHA224",
            "RSA-SHA256",
            "RSA-SHA3-224",
            "RSA-SHA3-256",
            "RSA-SHA3-384",
            "RSA-SHA3-512",
            "RSA-SHA384",
            "RSA-SHA512",
            "RSA-SHA512/224",
            "RSA-SHA512/256",
            "md5",
            "md5-sha1",
            "md5WithRSAEncryption",
            "sha1",
            "sha1WithRSAEncryption",
            "sha224",
            "sha224WithRSAEncryption",
            "sha256",
            "sha256WithRSAEncryption",
            "sha3-224",
            "sha3-256",
            "sha3-384",
            "sha3-512",
            "sha384",
            "sha384WithRSAEncryption",
            "sha512",
            "sha512-224",
            "sha512-224WithRSAEncryption",
            "sha512-256",
            "sha512-256WithRSAEncryption",
            "sha512WithRSAEncryption",
        ]
        const chosen_algorithm = readlineSync.keyInSelect(algorithm_list, 'Choose a Hashing Algorithm')
        const pass = readlineSync.question(chalk.red.italic("Please Input a password to encrypt it\n->  "), {
            hideEchoBack: true,
            mask: chalk.rgb(172, 172, 172)("-")
        })
        const salt_length = readlineSync.questionInt(chalk.red.italic("How long do you want your salt string ranging from (1-32)?\n "))
        setTimeout(() => {
            ColorLog("reset", "\n")
        }, 500)
        setTimeout(() => {
            let pwrd = hash(algorithm_list[chosen_algorithm], pass, genSalt(salt_length))
            let validated = validateHash(algorithm_list[chosen_algorithm], pass, pwrd.hashed_password, pwrd.salt)
            ColorLog("yellowBright", `<============== VALIDATION ==============>\nOriginal Password: ${pass}\nEncrypted Password: ${pwrd.hashed_password + pwrd.salt}\nHash Algorithm Type: ${algorithm_list[chosen_algorithm]}\nValidation Status: ${validated}\n\n`)
        }, 500)
    } else {
        const pass = readlineSync.question(chalk.red.italic("Please Input a password to encrypt it -> "), {
            hideEchoBack: true,
            mask: chalk.rgb(172, 172, 172)("-")
        })
        const salt_length = readlineSync.questionInt(chalk.red.italic("How long do you want your salt string ranging from (1-32)? "))
        setTimeout(() => {
            ColorLog("reset", "\n")
        }, 500)
        setTimeout(() => {
            let pwrd = hash("sha512", pass, genSalt(salt_length))
            let validated = validateHash("sha512", pass, pwrd.hashed_password, pwrd.salt)
            ColorLog("yellowBright", `<============== VALIDATION ==============>\nOriginal Password: ${pass}\nEncrypted Password: ${pwrd.hashed_password + pwrd.salt}\nHash Algorithm Type: sha512\nValidation Status: ${validated}\n\n`)
        }, 500)
    }
} else {
    return
}
