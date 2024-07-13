"""Initial migration.

Revision ID: 457cf3416019
Revises: 216fbc60947e
Create Date: 2024-07-13 19:21:10.464061

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '457cf3416019'
down_revision = '216fbc60947e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('like')
    op.drop_table('user')
    op.drop_table('joke')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('joke',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('title', sa.VARCHAR(length=100), nullable=False),
    sa.Column('text', sa.TEXT(), nullable=False),
    sa.Column('tags', sa.VARCHAR(length=100), nullable=True),
    sa.Column('likes', sa.INTEGER(), nullable=True),
    sa.Column('pub_date', sa.DATETIME(), nullable=False),
    sa.Column('user_id', sa.INTEGER(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('username', sa.VARCHAR(length=50), nullable=False),
    sa.Column('email', sa.VARCHAR(length=120), nullable=False),
    sa.Column('password', sa.VARCHAR(length=60), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.create_table('like',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('user_id', sa.INTEGER(), nullable=False),
    sa.Column('joke_id', sa.INTEGER(), nullable=False),
    sa.ForeignKeyConstraint(['joke_id'], ['joke.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
