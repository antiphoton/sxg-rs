import puppeteer from 'puppeteer';

function generateSxgUrl() {
  return `https://caoboxiao.com/.sxg/test.sxg?x=${Math.random()}`;
}

function createDataUrl(htmlContent: string): string {
  const base64 = Buffer.from(htmlContent).toString('base64');
  return `data:text/html;base64,${base64}`;
}

async function mockPageHtml(page: puppeteer.Page, htmlContent: string): Promise<void> {
  const URL = 'https://caoboxiao.com/mock.html';
  await page.setRequestInterception(true);
  page.on('request', (request) => {
    if (request.url() === URL) {
      request.respond({
        status: 200,
        contentType: 'text/html',
        body: htmlContent,
      });
    } else {
      request.continue();
    }
  })
  await page.goto(URL);
}

async function sleep(ms: number) {
  return await new Promise(resolve => setTimeout(resolve, ms));
}

describe('Chrome', () => {
  let browser: puppeteer.Browser;
  beforeAll(async () => {
    browser = await puppeteer.launch({
      headless: false,
    });
  });
  afterAll(async () => {
    await browser.close();
  });

  test('SXG works after link prefetch', async () => {
    const sxgUrl = generateSxgUrl();
    const page = await browser.newPage();
    await mockPageHtml(page, `
      <link rel="prefetch" href="${sxgUrl}">
    `);
    await page.goto(sxgUrl);
    expect(await page.content()).toMatchInlineSnapshot(`
"<!DOCTYPE html><html><head><meta charset=\\"utf-8\\">
</head><body><p>Yes, this message comes from a valid SXG.</p>
</body></html>"
`);
  });

  test('SXG fails if link without prefetch', async () => {
    const sxgUrl = generateSxgUrl();
    const page = await browser.newPage();
    await mockPageHtml(page, `
      <link href="${sxgUrl}">
    `)
    await page.goto(sxgUrl);
    expect(await page.content()).toMatchInlineSnapshot(`
"<!DOCTYPE html><html><head><meta charset=\\"utf-8\\">
</head><body><p>No, the SXG fails.</p>
</body></html>"
`);
  });

  test('SXG works as iframe src', async () => {
    const sxgUrl = generateSxgUrl();
    const page = await browser.newPage();
    await mockPageHtml(page, `
      <link rel="prefetch" href="${sxgUrl}">
      <iframe hidden src="${sxgUrl}"></iframe>
    `)
    const x1 = await page.$('iframe');
    const x2 = await x1?.contentFrame();
    const x3 = await x2?.content();
    expect(x3).toMatchInlineSnapshot(`
"<!DOCTYPE html><html><head><meta charset=\\"utf-8\\">
</head><body><p>No, the SXG fails.</p>
</body></html>"
`);
  });
})

describe('Headless chrome', () => {
  let browser: puppeteer.Browser;
  beforeAll(async () => {
    browser = await puppeteer.launch();
  });
  afterAll(async () => {
    await browser.close();
  });

  test('SXG works after link prefetch', async () => {
    const sxgUrl = generateSxgUrl();
    const page = await browser.newPage();
    await mockPageHtml(page, `
      <link rel="prefetch" href="${sxgUrl}">
    `);
    await page.goto(sxgUrl);
    expect(await page.content()).toMatchInlineSnapshot(`
"<!DOCTYPE html><html><head><meta charset=\\"utf-8\\">
</head><body><p>Yes, this message comes from a valid SXG.</p>
</body></html>"
`);
  });

  test('SXG fails if link without prefetch', async () => {
    const sxgUrl = generateSxgUrl();
    const page = await browser.newPage();
    await mockPageHtml(page, `
      <link href="${sxgUrl}">
    `)
    await page.goto(sxgUrl);
    expect(await page.content()).toMatchInlineSnapshot(`
"<!DOCTYPE html><html><head><meta charset=\\"utf-8\\">
</head><body><p>No, the SXG fails.</p>
</body></html>"
`);
  });

  test('SXG works as iframe src', async () => {
    const sxgUrl = generateSxgUrl();
    const page = await browser.newPage();
    await mockPageHtml(page, `
      <link rel="prefetch" href="${sxgUrl}">
      <iframe src="${sxgUrl}"></iframe>
    `)
    const x1 = await page.$('iframe');
    const x2 = await x1?.contentFrame();
    const x3 = await x2?.content();
    expect(x3).toMatchInlineSnapshot(`
"<!DOCTYPE html><html><head><meta charset=\\"utf-8\\">
</head><body><p>Yes, this message comes from a valid SXG.</p>
</body></html>"
`);
  });
})