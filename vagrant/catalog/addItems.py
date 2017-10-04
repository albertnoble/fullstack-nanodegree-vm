# Dummy information for the Database

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Categories, Base, Items, User

engine = create_engine('sqlite:///sportsEquipmentwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create dummy user
User1 = User(
    name="Robo Barista",
	email="tinnyTim@udacity.com",
    picture='https://pbs.twimg.com/profile_images/2671' +
    '170543/18debd694829ed78203a5a36dd364160_400x400.png'
)

session.add(User1)
session.commit()


category1 = Categories(user_id=1, name="Soccer")
session.add(category1)
session.commit()

category2 = Categories(user_id=1, name="Basketball")
session.add(category2)
session.commit()

category3 = Categories(user_id=1, name="Baseball")
session.add(category3)
session.commit()

category4 = Categories(user_id=1, name="Frisbee")
session.add(category4)
session.commit()

category5 = Categories(user_id=1, name="Snowboarding")
session.add(category5)
session.commit()

category6 = Categories(user_id=1, name="Rock Climbing")
session.add(category6)
session.commit()

category7 = Categories(user_id=1, name="Foosball")
session.add(category7)
session.commit()

category8 = Categories(user_id=1, name="Skating")
session.add(category8)
session.commit()

category9 = Categories(user_id=1, name="Hockey")
session.add(category9)
session.commit()

item1 = Items(
    user_id=1,
    name="Stick",
    description="You Hit the puck with it",
    categories=category9
)

session.add(item1)
session.commit()

item2 = Items(
    user_id=1,
    name="Googles",
    description="You put in on your eyes",
    categories=category5
)

session.add(item2)
session.commit()

item3 = Items(
    user_id=1,
    name="Snowboard",
    description="You can ride the snow with it",
    categories=category5
)

session.add(item3)
session.commit()

item4 = Items(
    user_id=1,
    name="Two Shinguards",
    description="Protects your shins",
    categories=category1
)

session.add(item4)
session.commit()

item5 = Items(
    user_id=1,
    name="Jersey",
    description="You wear it on your chest",
    categories=category1
)

session.add(item5)
session.commit()

item6 = Items(
    user_id=1,
    name="Soccer Cleats",
    description="Makes it easier to run",
    categories=category1
)

session.add(item6)
session.commit()

print("added menu items!")
