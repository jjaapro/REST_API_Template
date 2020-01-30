from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def create_ms_connector(connection):
    return create_ms_connector2(connection.username,
                                connection.password,
                                connection.database,
                                connection.address,
                                connection.port)


def create_ms_connector2(username, password, database, address='127.0.0.1', port=1433):
    return create_engine("mssql+pyodbc://{username}:{password}@{address}:{port}/{database}?driver=SQL+Server"
                         .format(address=address,
                                 port=port,
                                 username=username,
                                 password=password,
                                 database=database))


def create_postgre_connector(connection):
    return create_postgre_connector2(connection.username, connection.password, connection.database)


def create_postgre_connector2(username, password, database, address='127.0.0.1', port=5432):
    return create_engine("postgresql://{username}:{password}@{address}:{port}/{database}"
                         .format(username=username,
                                 password=password,
                                 database=database,
                                 address=address,
                                 port=port))


def create_session(engine):
    Session = sessionmaker(bind=engine)
    return Session()
