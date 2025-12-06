import bcrypt from 'bcryptjs';

async function verifyPassword() {
    const testHashes = [
        {
            hash: '$2a$10$8K1p/a0dRa1B0Z2QaKQWF.OU6TdR7EADqY7kU9tLk6Q9JkQY8JQKq',
            password: 'password123',
            description: 'Hash 1'
        },
        {
            hash: '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 
            password: '123456',
            description: 'Hash 2'
        }
    ];

    for (let test of testHashes) {
        const isValid = await bcrypt.compare(test.password, test.hash);
        console.log(`${test.description}:`);
        console.log(`  Password: "${test.password}"`);
        console.log(`  Hash: ${test.hash}`);
        console.log(`  Valid: ${isValid}`);
        console.log('---');
    }
}

// Agrega esto en verify-password.js
console.log('Bcrypt version:', bcrypt);
console.log('Bcrypt methods:', Object.keys(bcrypt));

verifyPassword();