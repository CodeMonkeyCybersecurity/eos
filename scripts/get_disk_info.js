const { getDiskInfo } = require('node-disk-info');

async function getDiskInfoExample() {
  try {
    const disks = await getDiskInfo();
    disks.forEach((disk) => {
      console.log(`Filesystem: ${disk.filesystem}`);
      console.log(`Used: ${disk.used}`);
      console.log(`Available: ${disk.available}`);
      console.log(`Capacity: ${disk.capacity}`);
      console.log('-----------------------------------');
    });
  } catch (error) {
    console.error(`Error retrieving disk info: ${error}`);
  }
}

getDiskInfoExample();
