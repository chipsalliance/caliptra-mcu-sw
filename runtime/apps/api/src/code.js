function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  locate=[...document.querySelectorAll('span.btn--label')].find(
    el => el.textContent.trim() === 'Locate Me'
  );
  locate.click();
  await sleep(2000);
  
  matchingSpans = Array.from(document.querySelectorAll('span.btn--label')).filter(span => span.textContent.trim() === 'Select Location');
  
  
  
  for (let i =0; i<matchingSpans.length; i++) {
    matchingSpans[i].click();
    await sleep(5000);
    
  try {
    office=document.querySelector('p.text--blue-dark-2.text--xmd.text--700.mb-0').textContent;
  
    console.log(office);
  } catch(error) {

  break;
  }
  
  const schedule= Array.from(document.querySelectorAll('div.ml-16.bp-sm\\:mr-60')).map(div => {
    const child = div.children[1]; // Access the second child element
    return child ? child.textContent.trim() : null;
  });
    
    console.log(schedule);
  back=[...document.querySelectorAll('span.btn--label')].find(
    el => el.textContent.trim() === 'Back'
  );
  
  await sleep(5000);
  back.click();
  await sleep(2000);
  locate=[...document.querySelectorAll('span.btn--label')].find(
    el => el.textContent.trim() === 'Locate Me'
  );
  locate.click();
  await sleep(2000);
  matchingSpans = Array.from(document.querySelectorAll('span.btn--label')).filter(span => span.textContent.trim() === 'Select Location');
  
  }
  