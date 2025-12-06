import bcrypt from 'bcryptjs';

async function diagnoseBcrypt() {
    console.log('🔧 DIAGNOSTICANDO BCRYPT...');
    
    // Test 1: Generar un nuevo hash
    console.log('\n1. GENERANDO NUEVO HASH:');
    const plainPassword = '123456';
    const saltRounds = 10;
    
    try {
        const newHash = await bcrypt.hash(plainPassword, saltRounds);
        console.log('✅ Hash generado:', newHash);
        
        // Test 2: Verificar el hash recién generado
        const isValid = await bcrypt.compare(plainPassword, newHash);
        console.log('✅ Verificación del nuevo hash:', isValid);
        
        // Test 3: Verificar con los hashes anteriores
        console.log('\n2. VERIFICANDO HASHES EXISTENTES:');
        const testHashes = [
            '$2a$10$8K1p/a0dRa1B0Z2QaKQWF.OU6TdR7EADqY7kU9tLk6Q9JkQY8JQKq',
            '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
        ];
        
        for (let hash of testHashes) {
            const result = await bcrypt.compare(plainPassword, hash);
            console.log(`Hash: ${hash.substring(0, 20)}...`);
            console.log(`Resultado: ${result}`);
        }
        
    } catch (error) {
        console.error('❌ Error:', error);
    }
}

diagnoseBcrypt();