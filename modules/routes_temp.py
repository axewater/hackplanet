from flask import jsonify
@bp.route('/admin/lab_editor/<int:lab_id>', methods=['GET', 'POST'])
@bp.route('/admin/lab_editor', methods=['GET', 'POST'])
@login_required
@admin_required
def lab_editor(lab_id=None):
    form = LabForm()
    lab = Lab.query.get(lab_id) if lab_id else None
    print(f"Editing lab: {lab}")
    if form.validate_on_submit():
        print(f"Form data: {form.data}")
        try:
            if lab:
                lab.name = form.name.data
                lab.image = form.image.data
                lab.description = form.description.data
            else:
                lab = Lab(
                    name=form.name.data,
                    image=form.image.data,
                    description=form.description.data,
                    date_created=datetime.utcnow()
                )
                db.session.add(lab)
            
            db.session.commit()
            flash('Lab saved successfully.', 'success')
            return redirect(url_for('main.lab_manager'))
        except Exception as e:
            db.session.rollback()
            print(f"Error saving lab: {str(e)}")
            flash('An error occurred while saving the lab. Please try again.', 'danger')

    if lab:
        form.name.data = lab.name
        form.image.data = lab.image
        form.description.data = lab.description

    return render_template('admin/lab_editor.html', form=form, lab=lab)


@bp.route('/admin/lab_manager', methods=['GET'])
@login_required
@admin_required
def lab_manager():
    print("Entered lab_manager route")
    labs = Lab.query.all()
    csrf_form = CsrfProtectForm()
    return render_template('admin/lab_manager.html', labs=labs, form=csrf_form)

@bp.route('/admin/delete_lab/<int:lab_id>', methods=['POST'])
@login_required
@admin_required
def delete_lab(lab_id):
    lab = Lab.query.get(lab_id)
    if lab:
        db.session.delete(lab)
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({
            'success': False,
            'message': 'Lab not found'
        }), 404

@bp.route('/admin/user_manager', methods=['GET', 'POST'])
@login_required
@admin_required
def usermanager():
    print("ADMIN USRMGR: username: Request method:", request.method)
    form = UserManagementForm()
    users_query = User.query.order_by(User.name).all()
    form.user_id.choices = [(user.id, user.name) for user in users_query]
    print(f"ADMIN USRMGR: User list : {users_query}")
    # Pre-populate the form when the page loads or re-populate upon validation failure
    if request.method == 'GET' or not form.validate_on_submit():
        # You could also use a default user here or based on some criteria
        default_user_id = request.args.get('user_id', 3)  # Example of getting a user_id from query parameters
        default_user = User.query.get(default_user_id)
        if default_user:
            form.user_id.data = default_user.id
            form.name.data = default_user.name
            form.email.data = default_user.email
            form.role.data = default_user.role
            form.state.data = default_user.state
            form.is_email_verified.data = default_user.is_email_verified
            form.about.data = default_user.about  # Pre-populate the 'about' field

    else:
        # This block handles the form submission for both updating and deleting users
        print(f"ADMIN USRMGR: Form data: {form.data}")
        user_id = form.user_id.data
        user = User.query.get(user_id)
        if not user:
            flash(f'User not found with ID: {user_id}', 'danger')
            return redirect(url_for('.usermanager'))  # Make sure the redirect is correct

        if form.submit.data:
            # Update user logic
            try:
                user.name = form.name.data or user.name
                user.email = form.email.data or user.email
                user.role = form.role.data or user.role
                user.state = form.state.data if form.state.data is not None else user.state
                user.is_email_verified = form.is_email_verified.data
                user.about = form.about.data
                print(f"ADMIN USRMGR: User updated: {user} about field : {user.about}")
                db.session.commit()
                flash('User updated successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Database error on update: {e}', 'danger')

        elif form.delete.data:
            # Delete user logic
            try:
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Database error on delete: {e}', 'danger')

    return render_template('admin/user_manager.html', form=form, users=users_query)


@bp.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    # Initialize the user creation form
    form = CreateUserForm()

    # Handle form submission
    if form.validate_on_submit():
        try:
            # Create a new user
            user = User(
                name=form.username.data,
                email=form.email.data.lower(),
                role='user',
                is_email_verified=True,  # Automatically set to True
                user_id=str(uuid4()),  # Generate a UUID for the user
                created=datetime.utcnow()
            )
            user.set_password(form.password.data)  # Set the user's password
            print(f"Debug: User created: {user}")
            db.session.add(user)
            db.session.commit()

            # Redirect to a success page
            flash('User created successfully.', 'success')
            return redirect(url_for('main.user_created'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')

    # Render the registration form
    return render_template('admin/create_user.html', form=form)