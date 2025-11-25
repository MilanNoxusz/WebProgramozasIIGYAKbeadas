const fs = require('fs');
const mysql = require('mysql2');
const path = require('path');

const dbOptions = {
    host: 'localhost',
    user: 'studb027',
    password: 'abc123', 
    database: 'db027',
    multipleStatements: true
};

const connection = mysql.createConnection(dbOptions);

function importData(fileName, tableName, columns) {
    const filePath = path.join(__dirname, 'DB', fileName);

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            console.error(`HIBA: Nem sikerült beolvasni a ${fileName} fájlt.`);
            return;
        }

        const lines = data.split(/\r?\n/);
        let count = 0;

        lines.forEach(line => {
            if (line.trim() === '') return;

            const values = line.split('\t'); // Tabulátor elválasztó

            if (values.length >= columns.length) {
                const placeholders = columns.map(() => '?').join(',');
                const sql = `INSERT IGNORE INTO ${tableName} (${columns.join(',')}) VALUES (${placeholders})`;
                
                const dataToInsert = values.slice(0, columns.length);

                connection.query(sql, dataToInsert, (err) => {
                    if (err) console.error(`Hiba a ${tableName} táblánál:`, err.message);
                });
                count++;
            }
        });
        console.log(`Feldolgozás alatt: ${fileName} -> ${count} sor.`);
    });
}

connection.connect(err => {
    if (err) {
        console.error('Hiba az adatbázis csatlakozáskor:', err);
        return;
    }
    console.log('Sikeres csatlakozás! Feltöltés indítása...');

    // 1. Kategóriák
    importData('kategoria.txt', 'kategoria', ['nev', 'ar']);

    // 2. Pizzák (késleltetve, hogy a kategória már bent legyen)
    setTimeout(() => {
        importData('pizza.txt', 'pizza', ['nev', 'kategorianev', 'vegetarianus']);
    }, 2000);

    // 3. Rendelések (még később)
    setTimeout(() => {
        importData('rendeles.txt', 'rendeles', ['pizzanev', 'darab', 'felvetel', 'kiszallitas']);
    }, 4000);

    // Kilépés a végén
    setTimeout(() => {
        console.log('Kész! A program leáll.');
        connection.end();
    }, 8000);
});