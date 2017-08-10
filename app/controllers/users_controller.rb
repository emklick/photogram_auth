class UsersController < ApplicationController
  def index
    @users = User.all
  end
  
  def show
    @user = User.find(params[:id])
    
    # @photos = Photo.where(:user_id => @user.id)
    @photos = @user.photos
  end
end