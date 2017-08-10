class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
         
  has_many :photos
  has_many :comments
  has_many :likes
  
  # has_may :liked_photos, :through => :likes, :source => :photo
  # has_may :commented_photos, :through => :comments, :source => :photo 
  
  validates :username, :presence => true, :uniqueness =>true
  # validates :username, :presence => true, :uniqueness: true => { :case_seneitive: false}
end
