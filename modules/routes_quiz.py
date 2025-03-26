from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from modules import db
from modules.models import Quiz, Question, UserQuizProgress, UserQuestionProgress, SystemMessage
from modules.forms import QuizForm, QuestionForm
from modules.utilities import admin_required

bp_quiz = Blueprint('bp_quiz', __name__)

@bp_quiz.context_processor
def utility_processor():
    def get_unread_message_count():
        if current_user.is_authenticated:
            return SystemMessage.query.filter(
                ~SystemMessage.read_by.contains(current_user)
            ).count()
        return 0
    return dict(get_unread_message_count=get_unread_message_count)

@bp_quiz.route('/admin/quiz_manager')
@login_required
@admin_required
def quiz_manager():
    quizzes = Quiz.query.all()
    for quiz in quizzes:
        if quiz.image:
            quiz.image_path = url_for('static', filename=f'library/images/quizes/{quiz.image}')
        else:
            quiz.image_path = url_for('static', filename='library/images/quizes/default_quiz_image.jpg')
    return render_template('admin/quiz_manager.html', quizzes=quizzes)

@bp_quiz.route('/admin/quiz_editor', methods=['GET', 'POST'])
@bp_quiz.route('/admin/quiz_editor/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def quiz_editor(quiz_id=None):
    form = QuizForm()
    quiz = Quiz.query.get(quiz_id) if quiz_id else None

    if form.validate_on_submit():
        if quiz:
            quiz.title = form.title.data
            quiz.description = form.description.data
            quiz.min_score = form.min_score.data
            quiz.image = form.image.data
            quiz.sequential = form.sequential.data
        else:
            quiz = Quiz(title=form.title.data, description=form.description.data, min_score=form.min_score.data, image=form.image.data, sequential=form.sequential.data)
            db.session.add(quiz)
        db.session.commit()
        flash('Quiz saved successfully.', 'success')
        return redirect(url_for('bp_quiz.quiz_manager'))

    if quiz:
        form.title.data = quiz.title
        form.description.data = quiz.description
        form.min_score.data = quiz.min_score
        form.image.data = quiz.image
        form.sequential.data = quiz.sequential

    return render_template('admin/quiz_editor.html', form=form, quiz=quiz)

@bp_quiz.route('/admin/delete_quiz/<int:quiz_id>', methods=['POST'])
@login_required
@admin_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get(quiz_id)
    if quiz:
        # Check for related questions
        if quiz.questions:
            flash('Cannot delete quiz. Please delete all questions first.', 'error')
            return redirect(url_for('bp_quiz.quiz_manager'))
        
        # Check for user progress records
        user_progress = UserQuizProgress.query.filter_by(quiz_id=quiz_id).first()
        if user_progress:
            flash('Cannot delete quiz. There are user progress records associated with this quiz.', 'error')
            return redirect(url_for('bp_quiz.quiz_manager'))
        
        try:
            db.session.delete(quiz)
            db.session.commit()
            flash('Quiz deleted successfully.', 'success')
        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"Error deleting quiz: {str(e)}")
            flash('An error occurred while deleting the quiz.', 'error')
    else:
        flash('Quiz not found.', 'error')
    return redirect(url_for('bp_quiz.quiz_manager'))

@bp_quiz.route('/admin/question_editor/<int:quiz_id>', methods=['GET', 'POST'])
@bp_quiz.route('/admin/question_editor/<int:quiz_id>/<int:question_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def question_editor(quiz_id, question_id=None):
    form = QuestionForm()
    quiz = Quiz.query.get_or_404(quiz_id)
    question = Question.query.get(question_id) if question_id else None

    if form.validate_on_submit():
        if question:
            # Check if there's any user progress for this question
            user_progress_exists = UserQuestionProgress.query.filter_by(question_id=question_id).first() is not None
            if user_progress_exists:
                flash('Warning: Editing this question will affect existing user progress.', 'warning')
            
            question.question_text = form.question_text.data
            question.option_a = form.option_a.data
            question.option_b = form.option_b.data
            question.option_c = form.option_c.data
            question.option_d = form.option_d.data
            question.correct_answer = form.correct_answer.data
            question.points = form.points.data
            question.image = form.image.data
            question.explanation = form.explanation.data
        else:
            question = Question(
                quiz_id=quiz_id,
                question_text=form.question_text.data,
                option_a=form.option_a.data,
                option_b=form.option_b.data,
                option_c=form.option_c.data,
                option_d=form.option_d.data,
                correct_answer=form.correct_answer.data,
                points=form.points.data,
                image=form.image.data,
                explanation=form.explanation.data
            )
            db.session.add(question)
        db.session.commit()
        flash('Question saved successfully.', 'success')
        return redirect(url_for('bp_quiz.quiz_editor', quiz_id=quiz_id))

    if question:
        form.question_text.data = question.question_text
        form.option_a.data = question.option_a
        form.option_b.data = question.option_b
        form.option_c.data = question.option_c
        form.option_d.data = question.option_d
        form.correct_answer.data = question.correct_answer
        form.points.data = question.points
        form.image.data = question.image
        form.explanation.data = question.explanation




        # Check if there's any user progress for this question
        user_progress_exists = UserQuestionProgress.query.filter_by(question_id=question_id).first() is not None
        if user_progress_exists:
            flash('Warning: Editing or deleting this question will affect existing user progress.', 'warning')

    return render_template('admin/question_editor.html', form=form, quiz=quiz, question=question)

@bp_quiz.route('/admin/delete_question/<int:question_id>', methods=['POST'])
@login_required
@admin_required
def delete_question(question_id):
    question = Question.query.get(question_id)
    if question:
        quiz_id = question.quiz_id
        
        # Delete related UserQuestionProgress entries
        UserQuestionProgress.query.filter_by(question_id=question_id).delete()
        
        # Update UserQuizProgress scores
        user_quiz_progresses = UserQuizProgress.query.filter_by(quiz_id=quiz_id).all()
        for progress in user_quiz_progresses:
            if progress.score >= question.points:
                progress.score -= question.points
        
        db.session.delete(question)
        db.session.commit()
        flash('Question and related progress data deleted successfully.', 'success')
        return redirect(url_for('bp_quiz.quiz_editor', quiz_id=quiz_id))
    else:
        flash('Question not found.', 'error')
        return redirect(url_for('bp_quiz.quiz_manager'))
