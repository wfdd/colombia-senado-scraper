
import ast
import asyncio
import re
import sqlite3
import sys

from aiohttp import ClientSession, TCPConnector
from lxml.html import document_fromstring, tostring
import uvloop
from yarl import URL


asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

base_url = URL('http://www.secretariasenado.gov.co/')

numeric_escape_match = re.compile(r'&#(\d+);')
email_match = re.compile(r'\n var addy\d+ = (.*);\n addy\d+ = addy\d+ \+ (.*);')


def deobfuscate_email(matches):
    email = ''.join(ast.literal_eval(i.strip())
                    for m in matches
                    for i in m.split('+'))
    email = numeric_escape_match.sub(lambda m: chr(int(m.group(1))), email)
    email = email.strip('-')
    return email


async def scrape_person(session, params):
    def extract_emails():
        emails = tostring(source).decode()
        emails = {deobfuscate_email(m.groups()) for m in email_match.finditer(emails)}
        if not emails:
            print(f'Could not find email in {profile_resp.url}', file=sys.stderr)
            return
        return ';'.join(sorted(emails,
                               key=lambda i: chr(0) if 'senado.gov.co' in i else i))

    def extract_photo():
        try:
            photo, = source.xpath('.//img[1]/@src')
        except ValueError:
            return
        return str(base_url.with_path(photo))

    def extract_other_item(caption, link=False):
        if isinstance(caption, tuple):
            return next(filter(None, (extract_other_item(i, link) for i in caption)),
                        [] if link else None)

        if link:
            val = source.xpath(f'''\
.//td[contains(string(.), "{caption}")]/following-sibling::td//a/@href''')
        else:
            val = source.xpath(f'''\
string(.//td[contains(string(.), "{caption}")]/following-sibling::td)''').strip()
            if not val or val.lower() in {'no tine', 'no tiene'}:
                return
        return val

    def extract_facebook():
        facebook, = (extract_other_item('FACEBOOK:', link=True) or
                     [extract_other_item('FACEBOOK:')])
        if not facebook:
            return

        facebook = URL('https://' + facebook.lstrip('/')
                       if not facebook.startswith('http') else facebook)
        return str(URL('https://www.facebook.com/').with_path(facebook.path))

    def extract_twitter():
        twitter = extract_other_item('TWITTER:')
        if twitter:
            twitter = ';'.join(t.replace('https://twitter.com/', '').lstrip('@')
                               for t in twitter.split(' - '))
        return twitter

    def extract_website():
        website = extract_other_item(('PAGINA WEB:', 'PÁGINA WEB:'), link=True)
        website = ';'.join(w for w in website
                           if not (w == '/false' or 'alvaroasthongiraldo' in w))
        if not website:
            website = extract_other_item(('PAGINA WEB:', 'PÁGINA WEB:'))
            website = ';'.join((w if w.startswith('http') else 'http://' + w
                                ).rstrip(',') for w in (website or '').splitlines())

        if 'correo electrónico' in website:
            print(f'Email found in {profile_resp.url}; skipping', file=sys.stderr)
            return
        return website or None

    async with session.get(base_url, params=sorted(params.items())) \
            as profile_resp:
        source, = (document_fromstring(await profile_resp.text())
                   .xpath('//div[@class = "art-article"]'))
    return lambda: (params['id'],
                    source.text_content().strip().splitlines()[0].strip(),
                    extract_photo(),
                    extract_other_item(('FILIACIÓN POLÍTICA:', 'FILIACION POLITICA:',
                                        'FILIACIÓNPOLÍTICA:')),
                    '2014',
                    extract_emails(),
                    extract_website(),
                    extract_other_item('TELÉFONO:'),
                    extract_facebook(),
                    extract_twitter(),
                    extract_other_item('LUGAR DE NACIMIENTO:'),
                    str(profile_resp.url))


async def gather_people():
    async with ClientSession(connector=TCPConnector(limit_per_host=8)) \
            as session:
        async with session.get(base_url / 'index.php/buscar-senador') as resp:
            source = document_fromstring(await resp.text())
        base_params = dict(i.xpath('./@name | ./@value') for i in source.xpath('''\
//form[@name = "ddaForm"]/input[@type = "hidden"]'''))
        return await asyncio.gather(*(scrape_person(session, {**base_params, 'id': i})
                                      for i in source.xpath('''\
//form[@name = "ddaForm"]/select[@name = "id"]/option[position() > 1]/@value''')))


def main():
    people = asyncio.get_event_loop().run_until_complete(gather_people())
    with sqlite3.connect('data.sqlite') as cursor:
        cursor.execute('''\
CREATE TABLE IF NOT EXISTS data
(id, name, image, 'group', term, email, website, phone, facebook, twitter,
 place_of_birth, source, UNIQUE (id))''')
        cursor.executemany('''\
INSERT OR REPLACE INTO data VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (p() for p in people))

if __name__ == '__main__':
    main()
