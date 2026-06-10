from influxdb import InfluxDBClient

db = InfluxDBClient('localhost', 8086)
db.switch_database('guardian')

print('=== ALERTS TAG KEYS ===')
result = db.query('SHOW TAG KEYS FROM alerts')
for p in result.get_points():
    print(p)

print('\n=== ALERTS SAMPLE ===')
result = db.query('SELECT * FROM alerts LIMIT 2')
for p in result.get_points():
    print(p)

print('\n=== ASSET TAG KEYS ===')
result = db.query('SHOW TAG KEYS FROM asset_impacts')
for p in result.get_points():
    print(p)

print('\n=== ASSET SAMPLE ===')
result = db.query('SELECT * FROM asset_impacts LIMIT 2')
for p in result.get_points():
    print(p)