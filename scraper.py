
import ast
import asyncio
import re
import sqlite3
from urllib.parse import urljoin, quote as urlquote
import sys

import aiohttp
from lxml.html import (document_fromstring as parse_html,
                       tostring as unparse_html)

base_url = 'http://www.secretariasenado.gov.co/'

numeric_escape_match = re.compile(r'&#(\d+);')
email_match = re.compile(r'\n var addy\d+ = (.*);\n addy\d+ = addy\d+ \+ (.*);')


def deobfuscate_email(matches):
    email = ''.join(ast.literal_eval(i.strip())
                    for m in matches
                    for i in m.split('+'))
    email = numeric_escape_match.sub(lambda m: chr(int(m.group(1))), email)
    return email


async def scrape_person(session, semaphore, params):
    def extract_email():
        emails = unparse_html(source).decode()
        emails = [deobfuscate_email(m.groups())
                  for m in email_match.finditer(emails)]
        if not emails:
            return print("Couldn't find email in " + repr(resp.url),
                         file=sys.stderr)
        return next((e for e in emails if 'senado.gov.co' in e), emails[0])

    def extract_photo():
        try:
            photo, = source.xpath('.//img[1]/@src')
        except ValueError:
            return
        return urljoin(base_url, urlquote(photo))

    def extract_other_item(caption):
        if isinstance(caption, tuple):
            return next(filter(None, map(extract_other_item, caption)),
                        None)
        val = ''.join(source.xpath(('string(.//td[contains(string(.), "{}")]'
                                    '/following-sibling::td)'
                                    ).format(caption))).strip()
        if caption == 'TWITTER:':
            val = val.lstrip('@').replace('https://twitter.com/', '')
        if not val or val.lower() in {'no tine', 'no tiene'}:
            return
        return val

    async def extract_website():
        try:
            website, = source.xpath('''\
.//td[contains(string(.), "PAGINA WEB:") or
      contains(string(.), "PÁGINA WEB:")]/following-sibling::td//a/@href''')
        except ValueError:
            website = extract_other_item(('PAGINA WEB:', 'PÁGINA WEB:'))
            if not website:
                return
            if not website.startswith('http'):
                website = ('http://' + website).rstrip(',')
        else:
            if website == '/false' or 'mailto:' in website:
                return
        try:
            with aiohttp.Timeout(5):
                (await session.head(website)).close()
        except aiohttp.errors.ClientError:
            return print(repr(website) + ' is unresponsive', file=sys.stderr)
        return website

    async with semaphore, session.get(base_url, params=params) as resp:
        source, = (parse_html(await resp.text())
                   .xpath('//div[@class = "art-article"]'))
    return (params['id'],
            source.text_content().strip().splitlines()[0].strip(),
            extract_photo(),
            extract_other_item('FILIACIÓN POLÍTICA:'),
            extract_email(),
            (await extract_website()),
            *map(extract_other_item,
                 ('TELÉFONO:', 'FACEBOOK:', 'TWITTER:', 'LUGAR DE NACIMIENTO:')),
            resp.url)


async def gather_people(session, semaphore):
    async with session.get(base_url + 'index.php/buscar-senador') as resp:
        source = parse_html(await resp.text())
    base_params = dict((*i.xpath('./@name'), *i.xpath('./@value'))
                       for i in source.xpath('//form[@name = "ddaForm"]'
                                             '/input[@type = "hidden"]'))
    people_ids = source.xpath('//form[@name = "ddaForm"]/select[@name = "id"]'
                              '/option[position() > 1]/@value')
    people = await asyncio.gather(*(scrape_person(session, semaphore,
                                                  {**base_params, 'id': i})
                                    for i in people_ids))
    return people


def main():
    loop = asyncio.get_event_loop()
    with aiohttp.ClientSession(loop=loop) as session:
        people = loop.run_until_complete(gather_people(session,
                                                       asyncio.Semaphore(10)))
    with sqlite3.connect('data.sqlite') as cursor:
        cursor.execute('''\
CREATE TABLE IF NOT EXISTS data
(id, name, image, 'group', email, website, phone, facebook, twitter,
 place_of_birth, source, UNIQUE (id))''')
        cursor.executemany('''\
INSERT OR REPLACE INTO data VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', people)

if __name__ == '__main__':
    main()
