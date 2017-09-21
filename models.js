const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 

const blogPostSchema = mongoose.Schema({
  author: {
    firstName: String,
    lastName: String
  },
  title: {type: String, required: true},
  content: {type: String},
  created: {type: Date, default: Date.now}
});


blogPostSchema.virtual('authorName').get(function() {
  return `${this.author.firstName} ${this.author.lastName}`.trim();
});

blogPostSchema.methods.apiRepr = function() {
  return {
    id: this._id,
    author: this.authorName,
    content: this.content,
    title: this.title,
    created: this.created
  };
}

const BlogPost = mongoose.model('BlogPost', blogPostSchema);



// ---------------------

const UserSchema = mongoose.Schema({
  username: {type: String, require: true, unique: true },
  password: {type: String, require: true }, 
  firstName: {type: String, require: true }, 
  lastName: {type: String, required: true }
}); 

UserSchema.methods.validatePassword = function(password) {
  return bcrypt.compare(password, this.password ); 
}; 

UserSchema.statics.hashPassword = function(password) { 
  return bcrypt.hash(password, 10); 
};

UserSchema.methods.apiRepr = function() {
  return {
    username: this.username, 
    firstName: this.firstName, 
    lastName: this.lastName
  }; 
}

const User = mongoose.model('User', UserSchema); 

module.exports = {BlogPost, User};