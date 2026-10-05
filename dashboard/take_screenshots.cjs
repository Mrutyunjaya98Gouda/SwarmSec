const puppeteer = require('puppeteer');

(async () => {
  try {
    const browser = await puppeteer.launch({
      headless: "new",
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    const page = await browser.newPage();
    
    // Set a good desktop resolution
    await page.setViewport({ width: 1280, height: 800 });
    
    console.log("Navigating to dashboard...");
    await page.goto('http://localhost:5173', { waitUntil: 'networkidle0' });
    
    // Wait for the UI to fully render the feed
    await page.waitForTimeout(3000); // 3 seconds to let React fetch and render
    
    console.log("Taking screenshot of main dashboard...");
    await page.screenshot({ path: '/home/cyberghost9813/.gemini/antigravity-ide/brain/33760228-89f4-4bae-b093-084fea4b135a/dashboard_main.png', fullPage: true });

    // Click the Peer Network tab
    console.log("Switching to Peer Network tab...");
    const tabs = await page.$$('button');
    for (let tab of tabs) {
      const text = await page.evaluate(el => el.textContent, tab);
      if (text.includes('Peer Network')) {
        await tab.click();
        break;
      }
    }
    
    // Wait for the tab to render
    await page.waitForTimeout(1000);
    
    console.log("Taking screenshot of peer network...");
    await page.screenshot({ path: '/home/cyberghost9813/.gemini/antigravity-ide/brain/33760228-89f4-4bae-b093-084fea4b135a/dashboard_peers.png', fullPage: true });

    await browser.close();
    console.log("Screenshots saved successfully.");
  } catch (error) {
    console.error("Error running puppeteer:", error);
    process.exit(1);
  }
})();
