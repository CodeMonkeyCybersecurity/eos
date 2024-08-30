const fs = require('fs');

// Read a file and print its contents
fs.readFile('example.txt', 'utf8', (err, data) => {
  if (err) {
    console.error(`Error reading file: ${err}`);
    return;
  }
  console.log(`File contents: ${data}`);
});
