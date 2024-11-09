from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column('user_preferences', sa.Column('background_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_user_preferences_background',
        'user_preferences', 'profile_backgrounds',
        ['background_id'], ['id']
    )

def downgrade():
    op.drop_constraint('fk_user_preferences_background', 'user_preferences', type_='foreignkey')
    op.drop_column('user_preferences', 'background_id')
